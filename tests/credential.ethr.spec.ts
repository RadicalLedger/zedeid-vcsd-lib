import { verifiable } from "../dist";
import documentLoader from "./assets/document-loader";

// const issuer = 'did:ethr:0x03dd7e099f73220214649abaa9dc0ad7925dc917a26ebfce63ce1d02fe4e47c273';
const issuerPrivateKey =
  "15ab1a84e0ea17f40442c67e060a2b59f2fbf0ae12a095d41480827aefd48966";
const issuerPublicKey =
  "03dd7e099f73220214649abaa9dc0ad7925dc917a26ebfce63ce1d02fe4e47c273";

// const holder = 'did:ethr:0x02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f';
// const holderPrivateKey = '4d05ba3d883ca102a49605936283aa3568617a6fd77b2cae82b3c2223b87c3d4';
const holderPublicKey =
  "02445020f2b0208357c05f9001d0614966654b3fe7c2ebe281afe4daefdd09c31f";

describe("(ETHR) Create and verify verifiable credential", () => {
  it("Create verifiable credential", async () => {
    const credential = {
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

    const result = await verifiable.credential.create({
      credential,
      holderPublicKey,
      issuerPrivateKey,
      issuanceDate: credential?.issuanceDate || new Date().toISOString(),
      documentLoader,
    });

    expect(result).not.toBeNull;
  }, 60000); // timeout - 1 minute

  it.only("Verify a verifiable credential", async () => {
    const credential = {
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

    /* create vc */
    const vc = await verifiable.credential.create({
      credential,
      holderPublicKey,
      issuerPrivateKey,
      issuanceDate: credential?.issuanceDate || new Date().toISOString(),
      documentLoader,
    });

    /* verify vc */
    const result = await verifiable.credential.verify({
      vc,
      holderPublicKey,
      issuerPublicKey,
      documentLoader,
    });

    expect(result?.verified).toBe(true);
  }, 60000); // timeout - 1 minute

  it("Verify a verifiable credential without holder public key", async () => {
    const credential = {
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

    /* create vc */
    const vc = await verifiable.credential.create({
      credential,
      issuerPrivateKey,
      issuanceDate: credential?.issuanceDate || new Date().toISOString(),
      documentLoader,
    });

    /* verify vc */
    const result = await verifiable.credential.verify({
      vc,
      documentLoader,
    });

    expect(result?.verified).toBe(true);
  }, 60000); // timeout - 1 minute
});
