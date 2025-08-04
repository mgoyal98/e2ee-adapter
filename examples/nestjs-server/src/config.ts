import { generateMultipleKeyPairs } from '../../../dist';

export const config = {
  keys: {},
};

export async function generateKeys() {
  const keys = await generateMultipleKeyPairs(['domain1']);
  config.keys = keys;
}
