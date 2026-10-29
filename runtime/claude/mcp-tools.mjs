export function negotiateProtocol(version) {
  if (typeof version !== 'string' || version.length > 64) throw Error('invalid-protocol-version');
  return ['2025-11-25','2025-06-18','2025-03-26','2024-11-05'].includes(version) ? version : '2025-11-25';
}
// Fixed stdio MCP vocabulary. No identity, credentials, endpoints or shell selectors.
// Transport injection is internal composition only; production uses the admitted FD.
const object = (required, properties) => ({type:'object', additionalProperties:false, required, properties});
const text = {type:'string'};
const number = {type:'integer', minimum:1};
export const TOOLS = Object.freeze([
  {name:'uas_peer', description:'Send typed peer traffic. Preserve operation id on retry; receipt is not completion.',
    inputSchema:object(['id','run_id','generation','kind','payload'],
      {id:text,run_id:text,generation:number,kind:{enum:['message','work-request','command']},payload:{type:'object'}})},
  {name:'uas_review', description:'Submit a current candidate or review result through the canonical Run review owner.',
    inputSchema:object(['id','run_id','generation','kind','payload'],{id:text,run_id:text,generation:number,kind:{enum:['submit-for-review','review-result']},payload:{type:'object'},observation_id:text})},
  {name:'gh', description:'Bounded canonical Forge routes; whole encoded request must fit one 64 KiB transport record. No shell or credentials. Unknown writes require explicit reconciliation with unchanged operation/body.',
    inputSchema:object(['id','argv'],{id:text,argv:{type:'array',items:text,maxItems:64},body:text,
      reconcile:object(['operation_id','audit_reference'],{operation_id:text,audit_reference:text})})}
]);
function fields(value, required, optional=[]) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || required.some(x => !Object.hasOwn(value,x))
      || Object.keys(value).some(x => !required.includes(x) && !optional.includes(x))) throw Error('invalid-tool-input');
}
function token(value) { if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(value)) throw Error('invalid-operation'); }
export function envelope(name, input) {
  if (name === 'uas_peer') {
    fields(input,['id','run_id','generation','kind','payload']); token(input.id); token(input.run_id);
    if (!Number.isSafeInteger(input.generation) || input.generation < 1
        || !['message','work-request','command'].includes(input.kind)) throw Error('invalid-peer-input');
  } else if (name === 'uas_review') {
    fields(input,['id','run_id','generation','kind','payload'],['observation_id']); token(input.id); token(input.run_id);
    if (!Number.isSafeInteger(input.generation) || input.generation < 1) throw Error('invalid-review-generation');
    if (input.observation_id !== undefined) token(input.observation_id);
    if (!['submit-for-review','review-result'].includes(input.kind)) throw Error('invalid-review-input');
  } else if (name === 'gh') {
    fields(input,['id','argv'],['body','reconcile']); token(input.id);
    if (!Array.isArray(input.argv) || input.argv.length < 1 || input.argv.length > 64
        || input.argv.some(x => typeof x !== 'string' || x.length > 8192 || x.includes('\0'))
        || (input.body !== undefined && (typeof input.body !== 'string' || Buffer.byteLength(input.body)>524288))) throw Error('invalid-forge-input');
    const argv = input.argv[0] === 'gh' ? input.argv.slice(1) : input.argv;
    const kind = ['issue','pr'].includes(argv[0]) && ['create','edit','close','reopen','comment','reply','review','dependency'].includes(argv[1]) ? 'forge-write' : 'forge-read';
    if (input.reconcile !== undefined) {
      fields(input.reconcile,['operation_id','audit_reference']); token(input.reconcile.operation_id); token(input.reconcile.audit_reference);
    }
    const original = {id:input.reconcile?.operation_id ?? input.id,kind,argv:input.argv,
      ...(input.body === undefined ? {} : {body:input.body})};
    return input.reconcile ? {id:input.id,kind:'forge-reconcile',audit_reference:input.reconcile.audit_reference,mutation:original} : original;
  } else throw Error('unknown-tool');
  if (!input.payload || typeof input.payload !== 'object' || Array.isArray(input.payload)) throw Error('invalid-payload');
  return input;
}
export async function invoke(channel, name, input) {
  const request = envelope(name,input);
  // This admitted dispatcher accepts one record. Do not activate Pi's optional
  // fragmented-request path or perform a partial large mutation.
  if (Buffer.byteLength(JSON.stringify({request_id:'0'.repeat(32),envelope:request}))>65536)
    throw Error('single-record-request-limit');
  const reply = await channel.request(request,{timeoutMs:45000});
  let failed = !reply.ok;
  if (reply.ok && name === 'gh') failed = request.kind === 'forge-reconcile'
    ? !['MATCHED','ABSENT'].includes(reply.receipt?.reconciliation?.status)
    : request.kind === 'forge-write'
      ? !(reply.receipt?.mutation?.status === 'OK' || ['ASSIGNED','ALREADY_ASSIGNED'].includes(reply.receipt?.assignment?.status))
      : reply.receipt?.observation?.completeness !== 'complete';
  return {content:[{type:'text',text:JSON.stringify(reply)}],isError:failed};
}
