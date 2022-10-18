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
    email: string;
    firstName: string;
    lastName: string;
    password: string;
    phoneNumber: string;
    birthDate: string;
    organizationId: string[];
    updatedAt: number;
    status: UserStatus;
    twoFATokenSecret: string | null;
    role: UserRole;
}
