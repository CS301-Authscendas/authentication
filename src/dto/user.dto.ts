export enum UserStatus {
    Approved = "approved",
    Pending = "pending",
}

export enum UserRole {
    Owner = "owner",
    Admin = "admin",
    User = "user",
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
