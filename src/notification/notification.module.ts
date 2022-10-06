import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { NotificationService } from "./notification.service";

@Module({
    imports: [ConfigModule.forRoot()],
    providers: [NotificationService],
    exports: [NotificationService],
})
export class NotificationModule {}
