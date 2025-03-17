import secrets
from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from schemas import UserRegistrationRequestSchema, UserRegistrationResponseSchema, UserActivationRequestSchema, \
    PasswordResetRequestSchema, PasswordResetCompleteRequestSchema, UserLoginResponseSchema, TokenRefreshRequestSchema, \
    TokenRefreshResponseSchema, UserLoginRequestSchema
from exceptions import BaseSecurityError, TokenExpiredError
from security.interfaces import JWTAuthManagerInterface
from security.token_manager import JWTAuthManager
from config.dependencies import get_jwt_auth_manager

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        statement = select(UserModel).where(UserModel.email == user_data.email)
        result = await db.execute(statement)
        user = result.scalars().first()

        if user:
            raise HTTPException(status_code=409, detail=f"A user with this email {user_data.email} already exists.")

        statement = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        result = await db.execute(statement)
        user_group = result.scalars().first()

        if not user_group:
            raise HTTPException(status_code=500, detail="Default user group not found")

        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id
        )

        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)

        token = ActivationTokenModel(user_id=new_user.id)
        db.add(token)
        await db.commit()

        return new_user

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    status_code=status.HTTP_200_OK,
)
async def activate(
        user_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user_query = select(UserModel).options(joinedload(UserModel.activation_token)).where(
        UserModel.email == user_data.email)
    user_result = await db.execute(user_query)
    user = user_result.scalar_one_or_none()

    if user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active.",
        )

    if not user.activation_token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    if user.activation_token.expires_at < datetime.now() or user.activation_token.token != user_data.token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    db.add(user)
    await db.flush()

    await db.delete(user.activation_token)
    await db.commit()
    return {
        "message": "User account activated successfully.",
    }


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def password_reset_request(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    user_query = select(UserModel).where(UserModel.email == data.email)
    user_result = await db.execute(user_query)
    user = user_result.scalar_one_or_none()

    if not user or not user.is_active:
        return {
            "message": "If you are registered, you will receive an email with instructions."
        }

    reset_token_query = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user == user)
    reset_token_result = await db.execute(reset_token_query)
    reset_token = reset_token_result.scalar_one_or_none()

    if reset_token:
        await db.delete(reset_token)
        await db.flush()
    reset_token = PasswordResetTokenModel(user=user)
    db.add(reset_token)
    await db.commit()
    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def reset_password_complete(
        data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    try:
        user_query = select(UserModel).options(
            joinedload(UserModel.activation_token)
        ).where(UserModel.email == data.email)

        user_result = await db.execute(user_query)
        user = user_result.scalar_one_or_none()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=400,
                detail="Invalid email or token.",
            )

        reset_token_query = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user == user)
        reset_token_result = await db.execute(reset_token_query)
        reset_token = reset_token_result.scalar_one_or_none()

        if not reset_token.token:
            await db.delete(reset_token)
            await db.commit()
            raise HTTPException(
                status_code=400,
                detail="Invalid email or token."
            )

        if reset_token.token != data.token or reset_token.expires_at < datetime.now():
            await db.delete(reset_token)
            await db.commit()
            raise HTTPException(
                status_code=400,
                detail="Invalid email or token."
            )

        user.password = data.password
        db.add(user)
        await db.flush()

        await db.delete(reset_token)
        await db.commit()
        return {
            "message": "Password reset successfully.",
        }

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserLoginResponseSchema)
async def login(
        data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        user_query = select(UserModel).where(UserModel.email == data.email)
        user_result = await db.execute(user_query)
        user = user_result.scalar_one_or_none()

        if not user or not user.verify_password(data.password):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password.",
            )
        if not user.is_active:
            raise HTTPException(
                status_code=403,
                detail="User account is not activated.",
            )
        user_data = data.model_dump()
        user_data.update({"user_id": user.id})

        raw_refresh_token = jwt_manager.create_refresh_token(user_data)
        refresh_token = RefreshTokenModel.create(user_id=user.id, days_valid=7, token=raw_refresh_token)
        access_token = jwt_manager.create_access_token(user_data)

        db.add(refresh_token)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token.token,
            "token_type": "bearer",
        }

    except SQLAlchemyError:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request.",
        )


@router.post(
    "/refresh/",
    status_code=status.HTTP_200_OK,
    response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
        data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        jwt_manager.verify_refresh_token_or_raise(data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=400,
            detail="Token has expired.",
        )

    refresh_token_query = select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    refresh_token_result = await db.execute(refresh_token_query)
    refresh_token = refresh_token_result.scalar_one_or_none()

    if not refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found.",
        )

    decoded_token = jwt_manager.decode_refresh_token(refresh_token.token)
    user_id = decoded_token["user_id"]

    user_query = select(UserModel).where(UserModel.id == user_id)
    user_result = await db.execute(user_query)
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    user_data = {
        "email": user.email,
        "user_id": user.id,
    }

    access_token = jwt_manager.create_access_token(user_data)

    return {
        "access_token": access_token
    }
