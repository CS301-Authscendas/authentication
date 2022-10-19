export enum UserStatus {
    Approved = "APPROVED",
    Pending = "PENDING",
}

export enum UserRole {
    Owner = "OWNER",
    Admin = "ADMIN",
    User = "USER",
}

export interface UserDTO {
    id: string;
    organizationId: string[];
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    status: UserStatus;
    birthDate: string;
    twoFATokenSecret: string | null;
    phoneNumber: string;
    updatedAt: number;
    role: UserRole;
}
