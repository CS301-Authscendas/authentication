import { IsNotEmpty, IsString } from "class-validator";

export class Auth0LoginDataDTO {
    @IsString()
    @IsNotEmpty()
    grant_type: string;

    @IsString()
    @IsNotEmpty()
    client_id: string;

    @IsString()
    @IsNotEmpty()
    client_secret: string;

    @IsString()
    @IsNotEmpty()
    username: string;

    @IsString()
    @IsNotEmpty()
    password: string;
}
