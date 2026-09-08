const paths={overview:'reports',targets:'targets',architecture:'graph','attack-paths':'attack-paths',scans:'scans',findings:'findings',policies:'policies',reports:'reports','self-audit':'self-audit'};
let token=sessionStorage.getItem('secgraph-token')||'';
const content=document.querySelector('#content'),title=document.querySelector('#title');
async function request(path){const response=await fetch(`/api/v1/${path}`,{headers:{Authorization:`Bearer ${token}`}});if(!response.ok)throw new Error(`${response.status} ${response.statusText}`);return response.json()}
async function load(view){title.textContent=view.split('-').map(x=>x[0].toUpperCase()+x.slice(1)).join(' ');document.querySelector('#panel-title').textContent=`${title.textContent} data`;const path=paths[view];if(!path){content.textContent='This view is populated by the corresponding scan module.';return}try{content.textContent=JSON.stringify(await request(path),null,2)}catch(error){content.textContent=String(error)}}
document.querySelector('#connect').addEventListener('click',async()=>{token=document.querySelector('#token').value;sessionStorage.setItem('secgraph-token',token);await load('overview')});
document.querySelectorAll('nav button').forEach(button=>button.addEventListener('click',()=>load(button.dataset.view)));
fetch('/api/v1/health').then(r=>r.json()).then(()=>{const status=document.querySelector('#status');status.textContent='Service healthy';status.classList.add('ok')});
