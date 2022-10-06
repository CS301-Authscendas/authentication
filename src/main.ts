import { ConfigService } from "@nestjs/config";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";
import { NotificationService } from "./notification/notification.service";

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    const configService = app.get(ConfigService);

    app.setGlobalPrefix("auth");

    const notificationService = app.get<NotificationService>(NotificationService);
    app.connectMicroservice(notificationService.getOptions());

    await app.startAllMicroservices();
    await app.listen(configService.get("PORT") ?? 3001);
}
bootstrap();
