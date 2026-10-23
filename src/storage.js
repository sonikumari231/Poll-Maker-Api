import { randomUUID } from "node:crypto";

let store = { users: [], polls: [] };
let pendingUpdate = Promise.resolve();

export async function getStore() {
  await pendingUpdate;
  return structuredClone(store);
}

export function updateStore(update) {
  const result = pendingUpdate.then(async () => {
    const updatedStore = structuredClone(store);
    const value = await update(updatedStore);
    store = updatedStore;
    return value;
  });

  pendingUpdate = result.catch(() => {});
  return result;
}

export function createId() {
  return randomUUID();
}
