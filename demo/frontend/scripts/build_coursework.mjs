import {build} from 'vite';
import {mkdir,writeFile,rename} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
const root=fileURLToPath(new URL('../../../',import.meta.url));
if(process.cwd()!==root.slice(0,-1))throw Error('Run from the coursework root');
const state=path.join(root,'runtime/coursework/frontend');
const out=path.join(state,'build-'+randomUUID());
await mkdir(state,{recursive:true});
await build({root:path.join(root,'demo/frontend'),configFile:false,cacheDir:path.join(state,'vite-cache'),
 build:{outDir:out,emptyOutDir:false,sourcemap:false}});
const pointer=path.join(state,'current.json'),temp=pointer+'.'+randomUUID();
await writeFile(temp,JSON.stringify({path:path.relative(root,out)},null,2)+'\n');
await rename(temp,pointer);
console.log('Coursework frontend built:',out);
