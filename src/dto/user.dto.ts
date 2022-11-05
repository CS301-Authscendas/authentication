import { IsArray, IsEmail, IsEnum, IsNotEmpty, IsNumber, IsString } from "class-validator";

export enum UserStatus {
    Approved = "approved",
    Pending = "pending",
}

export enum UserScopes {
    AdminDelete = "admin-delete",
    AdminWrite = "admin-write",
    AdminRead = "admin-read",
    User = "user",
}

export class OrganizationPermission {
    organizationId: string;
    permission: UserScopes[];
}

export class TwoFATokenObj {
    @IsString()
    @IsNotEmpty()
    token: string;

    @IsNumber()
    @IsNotEmpty()
    creationDate: number;
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

    twoFATokenObj: TwoFATokenObj | null;

    @IsString()
    phoneNumber: string;

    @IsNumber()
    updatedAt: number;

    // TODO: find validator for organization array.
    @IsNotEmpty()
    roles: OrganizationPermission[];

    getFullName(): string {
        return `${this.firstName} ${this.lastName}`;
    }
}
