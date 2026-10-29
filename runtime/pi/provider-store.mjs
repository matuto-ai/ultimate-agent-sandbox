// OAuth-only CredentialStore over Pi's own shared refresh lock. Never invoke
// AuthStorage's API-key command/env resolver or return a cached revoked record.
export function oauthDocument(text, provider) {
  try {
    if (typeof text !== 'string' || Buffer.byteLength(text)>16384) throw Error();
    const data=JSON.parse(text), auth=data?.[provider];
    if (!data || Array.isArray(data) || Object.keys(data).length!==1 || !Object.hasOwn(data,provider)
        || !auth || auth.type!=='oauth' || typeof auth.access!=='string' || !auth.access
        || typeof auth.refresh!=='string' || !auth.refresh || !Number.isFinite(auth.expires)) throw Error();
    return auth;
  } catch { throw Error('provider-auth-unavailable'); }
}

export function oauthStore(backend, provider, checkFile) {
  const locked = async (fn, options) => {
    try {
      checkFile();
      return await backend.withLockAsync(async current => fn(oauthDocument(current,provider)),options);
    } catch { throw Error('provider-auth-unavailable'); }
  };
  return {
    read: async (requested,options) => requested!==provider ? undefined : locked(auth=>({result:auth}),options),
    list: async options => locked(()=>({result:[{providerId:provider,type:'oauth'}]}),options),
    modify: async (requested,fn,options) => {
      if (requested!==provider) throw Error('provider-auth-unavailable');
      return locked(async current=>{
        const next=await fn(current);
        if(next===undefined) return {result:current};
        const encoded=JSON.stringify({[provider]:next});
        oauthDocument(encoded,provider);
        return {result:next,next:encoded};
      },options);
    },
    delete: async ()=>{throw Error('provider-auth-provisioning-is-human-owned');}
  };
}
