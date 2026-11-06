import React,{useEffect,useRef} from 'react';

export function DetailDrawer({title,children,onClose,onBack,initialFocusSelector,restoreFocusTo}){
 const panel=useRef(null);
 useEffect(()=>{
  const previous=restoreFocusTo||document.activeElement;const element=panel.current;
  const focusable=()=>Array.from(element.querySelectorAll('button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),textarea:not(:disabled),summary,[tabindex="0"]')).filter(n=>n.getClientRects().length);
  ((initialFocusSelector&&element.querySelector(initialFocusSelector))||focusable()[0]||element).focus();
  function key(e){
   if(e.key==='Escape'){e.preventDefault();e.stopPropagation();onClose();}
   if(e.key==='Tab'){
    const list=focusable();if(!list.length){e.preventDefault();return;}
    const first=list[0],last=list.at(-1);
    if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}
    else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}
   }
  }
  element.addEventListener('keydown',key);const oldOverflow=document.body.style.overflow;document.body.style.overflow='hidden';
  return()=>{element.removeEventListener('keydown',key);document.body.style.overflow=oldOverflow;if(previous?.isConnected)previous.focus();};
 },[]);
 return <div className="drawer-backdrop" onClick={e=>{if(e.target===e.currentTarget)onClose();}}><aside ref={panel} tabIndex={-1} className="drawer" role="dialog" aria-modal="true" aria-label={title}>
 <header><div>{onBack&&<button className="text-button" onClick={onBack}>← Back to previous detail</button>}<h2>{title}</h2></div><button onClick={onClose} aria-label="Close detail">×</button></header>{children}</aside></div>;
}
