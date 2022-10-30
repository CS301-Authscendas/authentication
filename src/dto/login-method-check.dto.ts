import { IsEnum, IsNotEmpty, IsString } from "class-validator";
import { LoginMethodEnum } from "./login-method.enum";

export class LoginMethodCheckDTO {
    @IsString()
    @IsNotEmpty()
    organizationId: string;

    @IsEnum(LoginMethodEnum)
    @IsNotEmpty()
    loginMethod: LoginMethodEnum;
}
