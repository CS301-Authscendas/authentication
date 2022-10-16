import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { AppController } from "./app.controller";
import { AppService } from "./app.service";
import { MqModule } from "./mq/mq.module";
import { NotificationModule } from "./notification/notification.module";
import { UserModule } from "./user/user.module";

@Module({
    imports: [ConfigModule.forRoot({ isGlobal: true }), UserModule, NotificationModule, MqModule],
    controllers: [AppController],
    providers: [AppService],
})
export class AppModule {}
