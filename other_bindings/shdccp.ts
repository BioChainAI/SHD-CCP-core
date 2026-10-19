// Reference typescript codec (ES2020 BigInt); no Form validation or security.
export interface Fields {
  core:number; scale:number; stream_slot:number; form_id:number;
  step_index:number; gate:number; structure:number; wheel_unit:number; cycle_step:number;
}
const defs:[keyof Fields,number,number][] = [
  ['core',0,32],['scale',32,4],['stream_slot',36,4],['form_id',40,4],
  ['step_index',44,4],['gate',48,8],['structure',56,2],['wheel_unit',58,3],['cycle_step',61,3]
];
export function encode(f:Fields):Uint8Array {
  let v=0n;
  for (const [key,offset,width] of defs) {
    const n=f[key];
    if(!Number.isSafeInteger(n) || n<0 || n>=2**width) throw new RangeError(key);
    v |= BigInt(n)<<BigInt(offset);
  }
  const out=new Uint8Array(8);
  for(let i=7;i>=0;i--){out[i]=Number(v & 255n);v>>=8n;}
  return out;
}
export function decode(b:Uint8Array):Fields {
  if(b.length!==8) throw new RangeError('8-byte wire word required');
  let w=0n;for(const x of b) w=(w<<8n)|BigInt(x);
  const obj={} as Fields;
  for(const [key,offset,width] of defs)
    obj[key]=Number((w>>BigInt(offset))&((1n<<BigInt(width))-1n));
  return obj;
}
