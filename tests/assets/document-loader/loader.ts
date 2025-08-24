import axios from 'axios';
import schemas from './offline-schemas';

const zedeid_api = 'https://www.offchaindids.zedeid.com/v2/';

const documentLoader = async (iri: string): Promise<any> => {
    let doc: any;
    let url = iri.split('#')[0];

    if (url.startsWith('did:')) {
        const didMethod = url.split(':')[1];
        url = `${zedeid_api}did/${didMethod}/${url}`;

        doc = await fetchDoc(url);
        doc = doc?.didDocument;
    } else {
        doc = await fetchDoc(url);
    }

    if (doc) {
        // console.log('document ==>> ', JSON.stringify(doc, null, 4));
        return { document: doc, documentUrl: url };
    }

    throw new Error(`iri ${iri} not supported`);
};

const fetchDoc = (url: string) => {
    return new Promise(async (resolve) => {
        var result: any;

        try {
            result = await axios.get(url);
        } catch (error) {}

        if (!result?.data && url in schemas) {
            return resolve(schemas[url]);
        }

        if (result?.status !== 200) return resolve(null);

        resolve(result?.data);
    });
};

export default documentLoader;
