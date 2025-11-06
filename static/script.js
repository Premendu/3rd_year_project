// static/script.js
// Small client-side niceties — clear password field placeholder on focus
document.addEventListener('DOMContentLoaded', function(){
  const pwd = document.querySelector('input[name="password"]');
  if(pwd){
    pwd.addEventListener('focus', ()=> pwd.placeholder = '');
    pwd.addEventListener('blur', ()=> pwd.placeholder = 'Enter password to analyze');
  }
});