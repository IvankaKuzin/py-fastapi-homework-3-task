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
from schemas import UserRegistrationRequestSchema, UserRegistrationResponseSchema
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface

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
