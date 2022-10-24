import { HttpModule } from "@nestjs/axios";
import { Module } from "@nestjs/common";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { JwtModule } from "@nestjs/jwt";
import { PassportModule } from "@nestjs/passport";
import { NotificationModule } from "../notification/notification.module";
import { UserModule } from "../user/user.module";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { JWTStrategy } from "./strategy/jwt.strategy";
import { LoginStrategy } from "./strategy/login.strategy";

@Module({
    imports: [
        ConfigModule,
        HttpModule,
        UserModule,
        NotificationModule,
        PassportModule,
        JwtModule.registerAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: async (configService: ConfigService) => {
                const privateKey = {
                    key: configService.get("JWT_PRIVATE_KEY"),
                    passphrase: configService.get("KEY_PASSPHRASE"),
                };
                return {
                    privateKey: privateKey,
                    signOptions: { expiresIn: "1d", algorithm: "RS256" },
                };
            },
        }),
    ],
    controllers: [AuthController],
    providers: [AuthService, LoginStrategy, JWTStrategy],
})
export class AuthModule {}
