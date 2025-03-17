from fastapi import HTTPException
from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators
from database.validators.accounts import validate_password_strength, validate_email


class UserRegistrationRequestSchema(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, email_val: str) -> str | None:
        validation_result = validate_email(email_val)
        if validation_result == ValueError:
            raise HTTPException(status_code=422, detail=validation_result)

        return email_val

    @field_validator("password")
    @classmethod
    def validate_password(cls, pass_val: str) -> str|None:
        validation_result = validate_password_strength(pass_val)
        if validation_result == ValueError:
            raise HTTPException(status_code=422, detail=validation_result)

        return pass_val


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str


class UserActivationRequestSchema(BaseModel):
    email: str
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    password: str
    token: str

    @field_validator("password")
    @classmethod
    def check_password_strength(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
