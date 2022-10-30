import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ClientProvider, RmqContext, RmqOptions, Transport } from "@nestjs/microservices";

@Injectable()
export class MqService {
    private transportMethod: string;
    private user: string;
    private password: string;
    private host: string;
    private port: string;

    constructor(configService: ConfigService) {
        this.transportMethod = configService.get<string>("RABBITMQ_TRANSPORT_METHOD") ?? "";
        this.user = configService.get<string>("RABBITMQ_USER") ?? "";
        this.password = configService.get<string>("RABBITMQ_PASSWORD") ?? "";
        this.port = configService.get<string>("RABBITMQ_PORT") ?? "";

        this.host =
            configService.get("NODE_ENV") === "production"
                ? configService.get("PRODUCTION_RABBITMQ_HOST") ?? ""
                : configService.get("RABBITMQ_HOST") ?? "";
    }

    getOptions(queueName: string, noAck = false): RmqOptions {
        return {
            transport: Transport.RMQ,
            options: {
                urls: [`${this.transportMethod}://${this.user}:${this.password}@${this.host}:${this.port}`],
                queue: queueName,
                noAck,
                persistent: true,
            },
        };
    }

    getClientProvider(queueName: string): ClientProvider {
        return {
            transport: Transport.RMQ,
            options: {
                urls: [`${this.transportMethod}://${this.user}:${this.password}@${this.host}:${this.port}`],
                queue: queueName,
                queueOptions: {
                    durable: true,
                },
            },
        };
    }

    ack(context: RmqContext) {
        const channel = context.getChannelRef();
        const originalMessage = context.getMessage();
        channel.ack(originalMessage);
    }
}
