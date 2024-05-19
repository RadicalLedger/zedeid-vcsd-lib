import { verifiable } from "../dist";
import documentLoader from "./assets/document-loader";

// const issuer = 'did:ethr:0x03dd7e099f73220214649abaa9dc0ad7925dc917a26ebfce63ce1d02fe4e47c273';
const issuerPrivateKey =
  "15ab1a84e0ea17f40442c67e060a2b59f2fbf0ae12a095d41480827aefd48966";
const issuerPublicKey =
  "03dd7e099f73220214649abaa9dc0ad7925dc917a26ebfce63ce1d02fe4e47c273";

// const holder = 'did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f';
const holderPrivateKey =
  "4d05ba3d883ca102a49605936283aa3568617a6fd77b2cae82b3c2223b87c3d4";
const holderPublicKey =
  "02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f";

const timeout = 60000; // 1 minute

describe("(ETHR) Create and verify verifiable presentation", () => {
  it(
    "Create verifiable presentation",
    async () => {
      const credential_1 = {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://d202eicx1ap3m7.cloudfront.net/credentials/microrewards/v0-01/microrewards-schema-v0-04.json",
        ],
        id: "http://localhost:8080/verify/did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f/8da736d605af5b0591d45c1e2f09264073fe5d3e9b77c1389e6097c247664a42",
        issuanceDate: "2023-04-14T00:00:00Z",
        type: ["VerifiableCredential"],
        issuer:
          "did:ethr:0x03dd7e099f73220214649abaa9dc0ad7925dc917a26ebfce63ce1d02fe4e47c273",
        credentialSubject: {
          type: ["EducationalAchievementBadge"],
          holder:
            "did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f",
          title: "Badge Title",
          description: "Successfully Completing the of Marketing Diploma",
          issuerLogo: "https://picsum.photos/500/500",
          issuerName: "Sample Organization",
          issuerUrl: "http://localhost:8080/issuer-profile/1",
          holderImage: "https://picsum.photos/300/300",
          holderName: "John Stark",
          holderProfileUrl:
            "http://localhost:8080/did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f/rewards",
          remarks: "Sample remark about this badge",
          visualPresentation: "https://picsum.photos/500/500",
          customAttribute: [],
        },
      };

      const credential_2 = {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://d202eicx1ap3m7.cloudfront.net/credentials/microrewards/v0-01/microrewards-schema-v0-04.json",
        ],
        id: "http://localhost:3002/verify/did:ethr:0x0Ff956599b1d6307aAa5B5076B856Bd93fd6b235/febacf38ee473284ef4276f380dbfe5e113b21fffc960c361b91ed6037d7bd09",
        issuanceDate: "2023-02-23T00:00:00Z",
        type: ["VerifiableCredential"],
        issuer:
          "did:ethr:0x03dd7e099f73220214649abaa9dc0ad7925dc917a26ebfce63ce1d02fe4e47c273",
        credentialSubject: {
          type: ["EducationalAchievementTranscript"],
          achievementInfo: {
            type: ["EducationalAchievementCertificate"],
            holder:
              "did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f",
            title: "Transcript Title",
            description: "Successfully Completing the of Marketing Diploma",
            issuerLogo: "https://picsum.photos/500/500",
            issuerName: "Sample Organization",
            issuerUrl: "http://localhost:8080/issuer-profile/1",
            holderImage: "https://picsum.photos/300/300",
            holderName: "John Stark",
            holderProfileUrl:
              "http://localhost:8080/did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f/rewards",
            conductedBy: "Mr. Stark",
            signature: ["https://picsum.photos/500/200"],
            remarks: "Sample remark about this transcript",
            visualPresentation: "https://picsum.photos/500/500",
          },
          subject: [],
          customAttribute: [],
        },
      };

      const verifiableCredential = await Promise.all([
        verifiable.credential.create({
          credential: credential_1,
          holderPublicKey,
          issuerPrivateKey,
          issuanceDate: credential_1?.issuanceDate || new Date().toISOString(),
          documentLoader,
        }),
        verifiable.credential.create({
          credential: credential_2,
          holderPublicKey,
          issuerPrivateKey,
          issuanceDate: credential_2?.issuanceDate || new Date().toISOString(),
          documentLoader,
        }),
      ]);

      const result = await verifiable.presentation.create({
        documentLoader: documentLoader,
        holderPrivateKey,
        verifiableCredential,
        holderDID:
          "did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f",
      });

      expect(result).not.toBeNull;
    },
    timeout
  );

  it(
    "Create a masked verifiable presentation",
    async () => {
      const credential_1 = {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://d202eicx1ap3m7.cloudfront.net/credentials/microrewards/v0-01/microrewards-schema-v0-04.json",
        ],
        id: "http://localhost:8080/verify/did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f/8da736d605af5b0591d45c1e2f09264073fe5d3e9b77c1389e6097c247664a42",
        issuanceDate: "2023-04-14T00:00:00Z",
        type: ["VerifiableCredential"],
        issuer:
          "did:ethr:0x03dd7e099f73220214649abaa9dc0ad7925dc917a26ebfce63ce1d02fe4e47c273",
        credentialSubject: {
          type: ["EducationalAchievementBadge"],
          holder:
            "did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f",
          title: "Badge Title",
          description: "Successfully Completing the of Marketing Diploma",
          issuerLogo: "https://picsum.photos/500/500",
          issuerName: "Sample Organization",
          issuerUrl: "http://localhost:8080/issuer-profile/1",
          holderImage: "https://picsum.photos/300/300",
          holderName: "John Stark",
          holderProfileUrl:
            "http://localhost:8080/did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f/rewards",
          remarks: "Sample remark about this badge",
          visualPresentation: "https://picsum.photos/500/500",
          customAttribute: [],
        },
      };

      const credential_2 = {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://d202eicx1ap3m7.cloudfront.net/credentials/microrewards/v0-01/microrewards-schema-v0-04.json",
        ],
        id: "http://localhost:3002/verify/did:ethr:0x0Ff956599b1d6307aAa5B5076B856Bd93fd6b235/febacf38ee473284ef4276f380dbfe5e113b21fffc960c361b91ed6037d7bd09",
        issuanceDate: "2023-02-23T00:00:00Z",
        type: ["VerifiableCredential"],
        issuer:
          "did:ethr:0x03dd7e099f73220214649abaa9dc0ad7925dc917a26ebfce63ce1d02fe4e47c273",
        credentialSubject: {
          type: ["EducationalAchievementTranscript"],
          achievementInfo: {
            type: ["EducationalAchievementCertificate"],
            holder:
              "did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f",
            title: "Transcript Title",
            description: "Successfully Completing the of Marketing Diploma",
            issuerLogo: "https://picsum.photos/500/500",
            issuerName: "Sample Organization",
            issuerUrl: "http://localhost:8080/issuer-profile/1",
            holderImage: "https://picsum.photos/300/300",
            holderName: "John Stark",
            holderProfileUrl:
              "http://localhost:8080/did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f/rewards",
            conductedBy: "Mr. Stark",
            signature: ["https://picsum.photos/500/200"],
            remarks: "Sample remark about this transcript",
            visualPresentation: "https://picsum.photos/500/500",
          },
          subject: [],
          customAttribute: [],
        },
      };

      const verifiableCredential = await Promise.all([
        verifiable.credential.create({
          credential: credential_1,
          holderPublicKey,
          issuerPrivateKey,
          issuanceDate: credential_1?.issuanceDate || new Date().toISOString(),
          documentLoader,
        }),
        verifiable.credential.create({
          credential: credential_2,
          holderPublicKey,
          issuerPrivateKey,
          issuanceDate: credential_2?.issuanceDate || new Date().toISOString(),
          documentLoader,
        }),
      ]);

      const result = await verifiable.presentation.create({
        documentLoader: documentLoader,
        holderPrivateKey,
        verifiableCredential,
        masks: [
          { title: true, holderImage: true },
          { achievementInfo: { remarks: true } },
        ],
        holderDID:
          "did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f",
      });

      expect(result).not.toBeNull;
    },
    timeout
  );

  it.only(
    "Verify a verifiable presentation",
    async () => {
      const credential_1 = {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://d202eicx1ap3m7.cloudfront.net/credentials/microrewards/v0-01/microrewards-schema-v0-04.json",
        ],
        id: "http://localhost:8080/verify/did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f/8da736d605af5b0591d45c1e2f09264073fe5d3e9b77c1389e6097c247664a42",
        issuanceDate: "2023-04-14T00:00:00Z",
        type: ["VerifiableCredential"],
        issuer:
          "did:ethr:0x03dd7e099f73220214649abaa9dc0ad7925dc917a26ebfce63ce1d02fe4e47c273",
        credentialSubject: {
          type: ["EducationalAchievementBadge"],
          holder:
            "did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f",
          title: "Badge Title",
          description: "Successfully Completing the of Marketing Diploma",
          issuerLogo: "https://picsum.photos/500/500",
          issuerName: "Sample Organization",
          issuerUrl: "http://localhost:8080/issuer-profile/1",
          holderImage: "https://picsum.photos/300/300",
          holderName: "John Stark",
          holderProfileUrl:
            "http://localhost:8080/did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f/rewards",
          remarks: "Sample remark about this badge",
          visualPresentation: "https://picsum.photos/500/500",
          customAttribute: [],
        },
      };

      const credential_2 = {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://d202eicx1ap3m7.cloudfront.net/credentials/microrewards/v0-01/microrewards-schema-v0-04.json",
        ],
        id: "http://localhost:3002/verify/did:ethr:0x0Ff956599b1d6307aAa5B5076B856Bd93fd6b235/febacf38ee473284ef4276f380dbfe5e113b21fffc960c361b91ed6037d7bd09",
        issuanceDate: "2023-02-23T00:00:00Z",
        type: ["VerifiableCredential"],
        issuer:
          "did:ethr:0x03dd7e099f73220214649abaa9dc0ad7925dc917a26ebfce63ce1d02fe4e47c273",
        credentialSubject: {
          type: ["EducationalAchievementTranscript"],
          achievementInfo: {
            type: ["EducationalAchievementCertificate"],
            holder:
              "did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f",
            title: "Transcript Title",
            description: "Successfully Completing the of Marketing Diploma",
            issuerLogo: "https://picsum.photos/500/500",
            issuerName: "Sample Organization",
            issuerUrl: "http://localhost:8080/issuer-profile/1",
            holderImage: "https://picsum.photos/300/300",
            holderName: "John Stark",
            holderProfileUrl:
              "http://localhost:8080/did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f/rewards",
            conductedBy: "Mr. Stark",
            signature: ["https://picsum.photos/500/200"],
            remarks: "Sample remark about this transcript",
            visualPresentation: "https://picsum.photos/500/500",
          },
          subject: [],
          customAttribute: [],
        },
      };

      const verifiableCredential = await Promise.all([
        verifiable.credential.create({
          credential: credential_1,
          holderPublicKey,
          issuerPrivateKey,
          issuanceDate: credential_1?.issuanceDate || new Date().toISOString(),
          documentLoader,
        }),
        verifiable.credential.create({
          credential: credential_2,
          holderPublicKey,
          issuerPrivateKey,
          issuanceDate: credential_2?.issuanceDate || new Date().toISOString(),
          documentLoader,
        }),
      ]);

      const vp = await verifiable.presentation.create({
        documentLoader,
        holderPrivateKey,
        verifiableCredential,
        holderDID:
          "did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f",
      });

      const result = await verifiable.presentation.verify({
        vp,
        issuerPublicKey,
        holderPublicKey,
        documentLoader,
      });

      expect(result?.verified).toBe(true);
    },
    timeout
  );

  it(
    "Verify a verifiable presentation without issuer and holder public keys",
    async () => {
      const credential_1 = {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://d202eicx1ap3m7.cloudfront.net/credentials/microrewards/v0-01/microrewards-schema-v0-04.json",
        ],
        id: "http://localhost:8080/verify/did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f/8da736d605af5b0591d45c1e2f09264073fe5d3e9b77c1389e6097c247664a42",
        issuanceDate: "2023-04-14T00:00:00Z",
        type: ["VerifiableCredential"],
        issuer:
          "did:ethr:0x03dd7e099f73220214649abaa9dc0ad7925dc917a26ebfce63ce1d02fe4e47c273",
        credentialSubject: {
          type: ["EducationalAchievementBadge"],
          holder:
            "did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f",
          title: "Badge Title",
          description: "Successfully Completing the of Marketing Diploma",
          issuerLogo: "https://picsum.photos/500/500",
          issuerName: "Sample Organization",
          issuerUrl: "http://localhost:8080/issuer-profile/1",
          holderImage: "https://picsum.photos/300/300",
          holderName: "John Stark",
          holderProfileUrl:
            "http://localhost:8080/did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f/rewards",
          remarks: "Sample remark about this badge",
          visualPresentation: "https://picsum.photos/500/500",
          customAttribute: [],
        },
      };

      const credential_2 = {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://d202eicx1ap3m7.cloudfront.net/credentials/microrewards/v0-01/microrewards-schema-v0-04.json",
        ],
        id: "http://localhost:3002/verify/did:ethr:0x0Ff956599b1d6307aAa5B5076B856Bd93fd6b235/febacf38ee473284ef4276f380dbfe5e113b21fffc960c361b91ed6037d7bd09",
        issuanceDate: "2023-02-23T00:00:00Z",
        type: ["VerifiableCredential"],
        issuer:
          "did:ethr:0x03dd7e099f73220214649abaa9dc0ad7925dc917a26ebfce63ce1d02fe4e47c273",
        credentialSubject: {
          type: ["EducationalAchievementTranscript"],
          achievementInfo: {
            type: ["EducationalAchievementCertificate"],
            holder:
              "did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f",
            title: "Transcript Title",
            description: "Successfully Completing the of Marketing Diploma",
            issuerLogo: "https://picsum.photos/500/500",
            issuerName: "Sample Organization",
            issuerUrl: "http://localhost:8080/issuer-profile/1",
            holderImage: "https://picsum.photos/300/300",
            holderName: "John Stark",
            holderProfileUrl:
              "http://localhost:8080/did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f/rewards",
            conductedBy: "Mr. Stark",
            signature: ["https://picsum.photos/500/200"],
            remarks: "Sample remark about this transcript",
            visualPresentation: "https://picsum.photos/500/500",
          },
          subject: [],
          customAttribute: [],
        },
      };

      const verifiableCredential = await Promise.all([
        verifiable.credential.create({
          credential: credential_1,
          issuerPrivateKey,
          issuanceDate: credential_1?.issuanceDate || new Date().toISOString(),
          documentLoader,
        }),
        verifiable.credential.create({
          credential: credential_2,
          issuerPrivateKey,
          holderPublicKey,
          issuanceDate: credential_2?.issuanceDate || new Date().toISOString(),
          documentLoader,
        }),
      ]);

      const vp = await verifiable.presentation.create({
        documentLoader,
        holderPrivateKey,
        verifiableCredential,
        holderDID:
          "did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f",
      });

      const result = await verifiable.presentation.verify({
        vp,
        documentLoader,
      });

      expect(result?.verified).toBe(true);
    },
    timeout
  );

  it(
    "Verify a masked verifiable presentation without issuer and holder public keys",
    async () => {
      const credential_1 = {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://d202eicx1ap3m7.cloudfront.net/credentials/microrewards/v0-01/microrewards-schema-v0-04.json",
        ],
        id: "http://localhost:8080/verify/did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f/8da736d605af5b0591d45c1e2f09264073fe5d3e9b77c1389e6097c247664a42",
        issuanceDate: "2023-04-14T00:00:00Z",
        type: ["VerifiableCredential"],
        issuer:
          "did:ethr:0x03dd7e099f73220214649abaa9dc0ad7925dc917a26ebfce63ce1d02fe4e47c273",
        credentialSubject: {
          type: ["EducationalAchievementBadge"],
          holder:
            "did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f",
          title: "Badge Title",
          description: "Successfully Completing the of Marketing Diploma",
          issuerLogo: "https://picsum.photos/500/500",
          issuerName: "Sample Organization",
          issuerUrl: "http://localhost:8080/issuer-profile/1",
          holderImage: "https://picsum.photos/300/300",
          holderName: "John Stark",
          holderProfileUrl:
            "http://localhost:8080/did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f/rewards",
          remarks: "Sample remark about this badge",
          visualPresentation: "https://picsum.photos/500/500",
          customAttribute: [],
        },
      };

      const credential_2 = {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://d202eicx1ap3m7.cloudfront.net/credentials/microrewards/v0-01/microrewards-schema-v0-04.json",
        ],
        id: "http://localhost:3002/verify/did:ethr:0x0Ff956599b1d6307aAa5B5076B856Bd93fd6b235/febacf38ee473284ef4276f380dbfe5e113b21fffc960c361b91ed6037d7bd09",
        issuanceDate: "2023-02-23T00:00:00Z",
        type: ["VerifiableCredential"],
        issuer:
          "did:ethr:0x03dd7e099f73220214649abaa9dc0ad7925dc917a26ebfce63ce1d02fe4e47c273",
        credentialSubject: {
          type: ["EducationalAchievementTranscript"],
          achievementInfo: {
            type: ["EducationalAchievementCertificate"],
            holder:
              "did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f",
            title: "Transcript Title",
            description: "Successfully Completing the of Marketing Diploma",
            issuerLogo: "https://picsum.photos/500/500",
            issuerName: "Sample Organization",
            issuerUrl: "http://localhost:8080/issuer-profile/1",
            holderImage: "https://picsum.photos/300/300",
            holderName: "John Stark",
            holderProfileUrl:
              "http://localhost:8080/did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f/rewards",
            conductedBy: "Mr. Stark",
            signature: ["https://picsum.photos/500/200"],
            remarks: "Sample remark about this transcript",
            visualPresentation: "https://picsum.photos/500/500",
          },
          subject: [],
          customAttribute: [],
        },
      };

      const verifiableCredential = await Promise.all([
        verifiable.credential.create({
          credential: credential_1,
          issuerPrivateKey,
          issuanceDate: credential_1?.issuanceDate || new Date().toISOString(),
          documentLoader,
        }),
        verifiable.credential.create({
          credential: credential_2,
          issuerPrivateKey,
          holderPublicKey,
          issuanceDate: credential_2?.issuanceDate || new Date().toISOString(),
          documentLoader,
        }),
      ]);

      const vp = await verifiable.presentation.create({
        documentLoader,
        holderPrivateKey,
        verifiableCredential,
        holderDID:
          "did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f",
        masks: [{ title: true, holderImage: true }],
      });

      const result = await verifiable.presentation.verify({
        vp,
        documentLoader,
      });

      expect(result?.verified).toBe(true);
    },
    timeout
  );
});
