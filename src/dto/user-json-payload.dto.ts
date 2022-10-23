import { IsEmail, IsNotEmpty, IsString } from "class-validator";

// Consistent with Bank SSO JWT.
export class UserJSONPayload {
    @IsString()
    @IsNotEmpty()
    id: string;

    @IsEmail()
    @IsNotEmpty()
    email: string;
}
