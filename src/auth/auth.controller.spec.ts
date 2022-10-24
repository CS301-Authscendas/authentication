import { HttpModule } from "@nestjs/axios";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { JwtModule } from "@nestjs/jwt";
import { PassportModule } from "@nestjs/passport";
import { Test, TestingModule } from "@nestjs/testing";
import { NotificationModule } from "../notification/notification.module";
import { UserModule } from "../user/user.module";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { JWTStrategy } from "./strategy/jwt.strategy";
import { LoginStrategy } from "./strategy/login.strategy";

describe("AuthController", () => {
    let controller: AuthController;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
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
        }).compile();

        controller = module.get<AuthController>(AuthController);
    });

    it("should be defined", () => {
        expect(controller).toBeDefined();
    });
});
