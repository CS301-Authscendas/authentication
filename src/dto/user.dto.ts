export enum UserStatus {
    Approved = "Approved",
    Pending = "Pending",
}

export interface UserDTO {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    password: string;
    birthDate: string;
    organizationId: string[];
    updatedAt: number;
    status: UserStatus;
    twoFATokenSecret: string | null;
}
