// Account-free actual Pi tool runner; no model chooses these fixture calls.
import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
export default async function(pi) {
  const {fauxProvider,fauxAssistantMessage,fauxToolCall}=await import(pathToFileURL(process.env.UAS_PI_FAUX_MODULE));
  const faux=fauxProvider({tokensPerSecond:100000}); pi.registerProvider(faux.provider);
  const finish=context=>{
    fs.appendFileSync(process.env.UAS_PI_LIBRARY_OBSERVATIONS,JSON.stringify(context)+'\n');
    return fauxAssistantMessage('Scripted native behavior complete; no inference.');
  };
  faux.setResponses([finish]);
  pi.registerCommand('fixture-native-files',{description:'Test-only native read sequence',handler:async args=>{
    const calls=JSON.parse(Buffer.from(args,'base64url'));
    faux.setResponses([...calls.map(call=>context=>{
      fs.appendFileSync(process.env.UAS_PI_LIBRARY_OBSERVATIONS,JSON.stringify(context)+'\n');
      return fauxAssistantMessage(fauxToolCall(call.name,call.input),{stopReason:'toolUse'});
    }),finish]);
  }});
}
