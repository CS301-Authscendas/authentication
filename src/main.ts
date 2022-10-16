import { ConfigService } from "@nestjs/config";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    const configService = app.get(ConfigService);

    app.setGlobalPrefix("auth");

    // Consumer queues:
    // const mqService = app.get<MqService>(MqService);
    // app.connectMicroservice(mqService.getOptions("user"));
    // app.connectMicroservice(mqService.getOptions("notification"));

    await app.startAllMicroservices();
    await app.listen(configService.get("PORT") ?? 3001);
}
bootstrap();
