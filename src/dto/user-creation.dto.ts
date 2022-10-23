import { IsEmail, IsNotEmpty, IsString } from "class-validator";

export class UserCreationDTO {
    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsString()
    @IsNotEmpty()
    firstName: string;

    @IsString()
    @IsNotEmpty()
    lastName: string;

    @IsString()
    @IsNotEmpty()
    phoneNumber: string;

    @IsString()
    @IsNotEmpty()
    birthDate: string;

    @IsString()
    @IsNotEmpty()
    password: string;
}
