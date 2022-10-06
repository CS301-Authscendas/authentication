import { ConfigModule } from "@nestjs/config";
import { Test, TestingModule } from "@nestjs/testing";
import { AppController } from "./app.controller";
import { NotificationModule } from "./notification/notification.module";
import { NotificationService } from "./notification/notification.service";
import { UserModule } from "./user/user.module";
import { UserService } from "./user/user.service";

describe("AppController", () => {
    let appController: AppController;

    beforeEach(async () => {
        const app: TestingModule = await Test.createTestingModule({
            imports: [ConfigModule.forRoot(), UserModule, NotificationModule],
            controllers: [AppController],
            providers: [UserService, NotificationService],
        }).compile();

        appController = app.get<AppController>(AppController);
    });

    describe("root", () => {
        it('should return "Auth service is awake!"', () => {
            expect(appController.healthCheck()).toBe("Auth service is awake!");
        });
    });
});
