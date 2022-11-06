import { BadRequestException, CACHE_MANAGER, Inject, Injectable, InternalServerErrorException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { KMS } from "aws-sdk";
import base64url from "base64url";
import { Cache } from "cache-manager";
import { decode, Jwt, verify } from "jsonwebtoken";
import { UserJSONPayload } from "../dto/user-json-payload.dto";
import { UserJWTData } from "../dto/user-jwt-data.dto";
import { UtilHelper } from "../utils";

@Injectable()
export class KmsService {
    private awsKmsClient: KMS;
    private CACHE_ID = "kmsKeyId";

    constructor(
        private readonly configService: ConfigService,
        @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
    ) {
        const awsAccessKeyId = this.configService.get("AWS_ACCESS_KEY_ID");
        const awsSecretAccessKey = this.configService.get("AWS_SECRET_ACCESS_KEY");
        const awsRegion = this.configService.get("AWS_REGION");

        if (UtilHelper.isProduction() && !(awsAccessKeyId && awsSecretAccessKey && awsRegion)) {
            throw new InternalServerErrorException("AWS credentials are missing");
        }

        this.awsKmsClient = new KMS({
            credentials: {
                accessKeyId: awsAccessKeyId,
                secretAccessKey: awsSecretAccessKey,
            },
            region: awsRegion,
        });
    }

    validateSsoToken(jwtToken: string, key: string): boolean {
        try {
            verify(jwtToken, key, { algorithms: ["RS256"] });
        } catch (error) {
            return false;
        }
        return true;
    }

    async sign(payload: any): Promise<string> {
        const now = Date.now();
        const tomorrow = new Date();
        tomorrow.setDate(tomorrow.getDate() + 1);

        const tokenPayload = {
            iat: Math.floor(now / 1000),
            exp: Math.floor(tomorrow.getTime() / 1000),
            ...payload,
        };

        const tokenHeader = {
            alg: "RS256",
            typ: "JWT",
        };

        const keyId = await this.getKeyId();
        const { encodedPayload, encodedHeader } = this.encodePayload(tokenPayload, tokenHeader);
        const encodedMessage = Buffer.from(`${encodedHeader}.${encodedPayload}`);

        const token = await this.awsKmsClient
            .sign({
                Message: encodedMessage,
                KeyId: keyId as string,
                SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256",
                MessageType: "RAW",
            })
            .promise();

        if (!token.Signature) {
            throw new InternalServerErrorException("Something went wrong with generating a JWT signature");
        }

        const signature = token.Signature.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

        return `${encodedHeader}.${encodedPayload}.${signature}`;
    }

    private encodePayload(payload: any, header: any) {
        return {
            encodedPayload: base64url(JSON.stringify(payload)),
            encodedHeader: base64url(JSON.stringify(header)),
        };
    }

    decodeToken(token: string): Jwt | null {
        return decode(token, { complete: true });
    }

    async verifyAndDecode(token: string): Promise<UserJSONPayload> {
        const keyId = await this.getKeyId();

        try {
            const result = this.decodeToken(token);

            if (!result) {
                throw new BadRequestException("Missing JWT payload for hosted login");
            }

            const { header, payload, signature } = result;
            const { encodedPayload, encodedHeader } = this.encodePayload(payload, header);

            await this.awsKmsClient
                .verify({
                    Message: Buffer.from(`${encodedHeader}.${encodedPayload}`),
                    KeyId: keyId as string,
                    SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256",
                    MessageType: "RAW",
                    Signature: Buffer.from(signature, "base64"),
                })
                .promise();

            return payload as UserJWTData;
        } catch (error) {
            throw new BadRequestException(error?.message || error?.code || "Invalid JWT token");
        }
    }

    private async getKeyId(): Promise<string> {
        let keyId = await this.cacheManager.get(this.CACHE_ID);

        if (!keyId) {
            keyId = await this.fetchKeys();
        }
        return keyId as string;
    }

    private async fetchKeys() {
        const rawKeyIds = await this.awsKmsClient.listKeys().promise();

        if (!rawKeyIds.Keys) {
            throw new InternalServerErrorException("No keys are fetched from AWS KMS");
        }

        const keyMetadataPromises = rawKeyIds.Keys.map((key) => {
            if (key.KeyId) {
                return this.awsKmsClient.describeKey({ KeyId: key.KeyId }).promise();
            }
        });

        const keyMetadata = await Promise.all(keyMetadataPromises);
        const sortedKeyMetadata = keyMetadata
            .filter((key) => key?.KeyMetadata?.Description?.includes("authcendas") && key?.KeyMetadata?.Enabled)
            .sort((a, b) => {
                const aCreationDate = a?.KeyMetadata?.CreationDate;
                const bCreationDate = b?.KeyMetadata?.CreationDate;

                if (!(aCreationDate && bCreationDate)) {
                    throw new InternalServerErrorException("Missing key metadata");
                }

                return aCreationDate.getTime() - bCreationDate.getTime();
            });

        if (sortedKeyMetadata.length === 0) {
            throw new InternalServerErrorException("There are no available signing keys!");
        }

        const selectedKeyId = sortedKeyMetadata[0]!.KeyMetadata!.KeyId;

        await this.cacheManager.set(this.CACHE_ID, selectedKeyId);

        return selectedKeyId;
    }
}
