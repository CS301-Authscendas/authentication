import { UserRole } from "./user.dto";

export interface UserJSONPayload {
    id: string;
    role: UserRole;
}
