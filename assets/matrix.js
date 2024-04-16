/* TODO
window.addEventListener('DOMContentLoaded', (event) =>  {
    const canvas = document.createElement('canvas');
    document.body.appendChild(canvas);
    const ctx = canvas.getContext('2d');
    
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    const characters = 'ABCDEFGHIJKMNOPQRSTUWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    const charSize = 20;
    const columns = canvas.width / charSize;
    const drops = [];
    
    for(let i = 0; i < columns; i++)
    {
        drops[i] = 1;
    }
    
    const draw = () => {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            ctx.fillStyle = '#0F0'
            ctx.font = charSize + 'px + monospace';

            for(let i = 0; i < drops.length; i++) {
                const text = characters.charAt(Math.floor(Math.random() * characters.length));
                ctx.filltext(text, i*charSize, drops[i]*charSize);

                if(drops[i]*charSize > canvas.height && Math.random()){
                    drops[i] = 0;
                }
                drops[i]++;
            }
    }

    function animate() {
        setInterval(draw, 30)
    }
    
    //animate();

})
*/