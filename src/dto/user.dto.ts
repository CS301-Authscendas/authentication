import { IsArray, IsEmail, IsEnum, IsNotEmpty, IsNumber, IsString } from "class-validator";

export enum UserStatus {
    Approved = "approved",
    Pending = "pending",
}

export enum UserRole {
    Owner = "owner",
    Admin = "admin",
    User = "user",
}

export class UserDTO {
    @IsString()
    @IsNotEmpty()
    id: string;

    @IsArray()
    @IsNotEmpty()
    organizationId: string[];

    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsString()
    @IsNotEmpty()
    password: string;

    @IsString()
    @IsNotEmpty()
    firstName: string;

    @IsString()
    @IsNotEmpty()
    lastName: string;

    @IsEnum(UserStatus)
    @IsNotEmpty()
    status: UserStatus;

    @IsString()
    birthDate: string;

    twoFATokenSecret: string | null;

    @IsString()
    phoneNumber: string;

    @IsNumber()
    updatedAt: number;

    @IsEnum(UserRole)
    @IsNotEmpty()
    role: UserRole;
}
