import { IsEmail, IsNotEmpty } from "class-validator";

// Consistent with Bank SSO JWT.
export class UserJSONPayload {
    @IsEmail()
    @IsNotEmpty()
    email: string;
}
