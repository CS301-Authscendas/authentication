import { IsEmail, IsNotEmpty, IsString } from "class-validator";

export class SuccessEmailRegistrationDTO {
    @IsString()
    @IsNotEmpty()
    name: string;

    @IsEmail()
    @IsNotEmpty()
    email: string;
}
