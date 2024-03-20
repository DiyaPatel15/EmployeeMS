function toggleSidebar(){
  const sidebar = document.querySelector('.sidebar');
  sidebar.classList.toggle('active');
}
function toggleMenu(){
  const menu = document.querySelector('.menu');
  menu.classList.toggle('active');
}
document.addEventListener('DOMContentLoaded', function(){
  const menu = document.querySelector('.menu');
  const sidebar = document.querySelector('.sidebar');
  const menuToggle = document.querySelector('.menu-toggle');
  const menuClose = document.querySelector('.menu-close');
  menuToggle.addEventListener('click', toggleMenu);
  menuClose.addEventListener('click', toggleMenu);
  document.addEventListener('click', function(e){
    if(e.target != menuToggle && e.target != menuClose && !menu.contains(e.target) && !sidebar.contains(e.target)){
      menu.classList.remove('active');
    }
  });
});

