import { HttpModule } from "@nestjs/axios";
import { ConfigModule } from "@nestjs/config";
import { PassportModule } from "@nestjs/passport";
import { Test, TestingModule } from "@nestjs/testing";
import { KmsModule } from "../kms/kms.module";
import { NotificationModule } from "../notification/notification.module";
import { OrganizationModule } from "../organization/organization.module";
import { UserModule } from "../user/user.module";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
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
                OrganizationModule,
                PassportModule,
                KmsModule,
            ],
            controllers: [AuthController],
            providers: [AuthService, LoginStrategy],
        }).compile();

        controller = module.get<AuthController>(AuthController);
    });

    it("should be defined", () => {
        expect(controller).toBeDefined();
    });
});
