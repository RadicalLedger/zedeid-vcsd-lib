import axios from 'axios';

const zedeid_api = 'https://www.offchaindids.zedeid.com/v2/';

const documentLoader = async (iri: string): Promise<any> => {
    let doc: any;
    let url = iri.split('#')[0];

    if (url.startsWith('did:')) {
        url = `${zedeid_api}did/${url}`;

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
        } catch (error) {
            console.log(error);
        }

        if (result?.status !== 200) return resolve(null);

        return resolve(result?.data);
    });
};


export default documentLoader;
