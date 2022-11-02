import { HttpModule } from "@nestjs/axios";
import { ConfigModule } from "@nestjs/config";
import { PassportModule } from "@nestjs/passport";
import { Test, TestingModule } from "@nestjs/testing";
import { NotificationModule } from "../notification/notification.module";
import { OrganizationModule } from "../organization/organization.module";
import { UserModule } from "../user/user.module";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { LoginStrategy } from "./strategy/login.strategy";

describe("AuthService", () => {
    let service: AuthService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            imports: [ConfigModule, HttpModule, UserModule, NotificationModule, OrganizationModule, PassportModule],
            controllers: [AuthController],
            providers: [AuthService, LoginStrategy],
        }).compile();

        service = module.get<AuthService>(AuthService);
    });

    it("should be defined", () => {
        expect(service).toBeDefined();
    });
});
