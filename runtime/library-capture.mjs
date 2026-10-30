// Shared explicit-capture contract; no Runtime registration or implicit capture.
import {randomUUID} from 'node:crypto';
// Capture is deliberately invoked. These are adapter results, not a second
// knowledge queue: the native tool call/result retains IDs for an explicit retry.
export function libraryCaptureTool(channel) {
  const token = {type:'string',pattern:'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$'};
  const result = (details, error = true) => ({content:[{type:'text',text:JSON.stringify(details)}],details,isError:error});
  const reason = value => typeof value === 'string' && /^[A-Z][A-Z0-9_]{0,95}$/.test(value);
  const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  const commit = value => typeof value === 'string' && /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(value);
  return {
    name:'library_enqueue',label:'Explicit Project Library capture',
    description:'Deliberately submit supplied knowledge to this Project Library. Never harvest transcripts or capture automatically. '
      +'Supply a stable request_id and the same capture on retry; each invocation uses a new Hub Command ID. '
      +'DURABLY_QUEUED alone proves publication; NOT_DURABLE is uncertain, not proof of absence. '
      +'Adapter transport failure has no Library outcome. Capture failure never blocks Run completion or context reset.',
    parameters:{type:'object',additionalProperties:false,required:['request_id','capture'],properties:{request_id:token,
      capture:{type:'object',additionalProperties:false,required:['type','title','body'],properties:{
        type:{type:'string',enum:['context','decision','research']},title:{type:'string'},body:{type:'string'},
        sources:{type:'array',items:{type:'object',additionalProperties:false,required:['resource'],properties:{
          resource:{type:'string'},title:{type:'string'},range:{type:'string'},sha256:{type:'string'}}}},
        hints:{type:'array',items:{type:'string'}}}}}},
    async execute(_toolCallId,input,signal) {
      const command_id=randomUUID();
      const request_id=input?.request_id;
      const evidence={request_id:typeof request_id==='string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(request_id)?request_id:null,command_id};
      // SDK checks the public schema; this guard also covers direct invocation.
      const object=v=>v && typeof v==='object' && !Array.isArray(v);
      if (!object(input) || Object.keys(input).sort().join(',')!=='capture,request_id' || evidence.request_id===null
          || !object(input.capture) || Object.keys(input.capture).some(k=>!['type','title','body','sources','hints'].includes(k)))
        return result({...evidence,status:'ADAPTER_REJECTED',reason:'INVALID_CAPTURE_INPUT',retryable:false});
      if (!channel) return result({...evidence,status:'TRANSPORT_UNAVAILABLE',reason:'HUB_UNAVAILABLE',retryable:true});
      let reply;
      try {
        // Snapshot exact input before async I/O; never normalize/rewrite content.
        const envelope=JSON.parse(JSON.stringify({id:command_id,kind:'library.enqueue',request_id,capture:input.capture}));
        if (Buffer.byteLength(JSON.stringify(envelope))>1048576)
          return result({...evidence,status:'ADAPTER_REJECTED',reason:'INPUT_LIMIT',retryable:false});
        reply=await channel.request(envelope,{signal,timeoutMs:45000});
      } catch {return result({...evidence,status:'TRANSPORT_UNAVAILABLE',reason:'HUB_UNAVAILABLE',retryable:true});}
      if (reply?.ok===false && reason(reply.error))
        return result({...evidence,status:'HUB_REFUSED',reason:reply.error,
          retryable:['LIBRARY_UNAVAILABLE','STORAGE_ERROR','CLOSED'].includes(reply.error)});
      const r=reply?.receipt;
      const keys='outcome,path,projection_sha,published_sha,queue_id,reason,request_id,retryable,visible';
      let valid=reply?.ok===true && object(r) && Object.keys(r).sort().join(',')===keys && r.request_id===request_id
        && typeof r.retryable==='boolean' && typeof r.visible==='boolean';
      if (valid && r.outcome==='DURABLY_QUEUED') valid=r.reason===null && !r.retryable && digest(r.queue_id)
        && r.path==='pending/'+r.queue_id+'.md' && commit(r.published_sha)
        && (r.projection_sha===null || commit(r.projection_sha)) && (!r.visible || r.projection_sha!==null);
      else if (valid && ['REJECTED','NOT_DURABLE'].includes(r.outcome)) valid=reason(r.reason)
        && r.retryable===(r.outcome==='NOT_DURABLE') && (r.queue_id===null || digest(r.queue_id))
        && r.path===null && r.published_sha===null && r.projection_sha===null && !r.visible;
      else valid=false;
      if (!valid) return result({...evidence,status:'TRANSPORT_UNAVAILABLE',reason:'INVALID_HUB_RESPONSE',retryable:true});
      return result({...evidence,status:'LIBRARY_OUTCOME',...r},r.outcome!=='DURABLY_QUEUED');
    },
  };
}

