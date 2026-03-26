const fs = require('fs');
const path = require('path');
const oldLink = 'https://tejaskp.in/login';
const newLink = 'https://www.tejaskpaisoftware.com/';

const dirs = [
    'public',
    '../curemolecules_static_preview'
];

dirs.forEach(dir => {
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.html'));
    files.forEach(f => {
        const p = path.join(dir, f);
        let content = fs.readFileSync(p, 'utf8');
        if (content.includes(oldLink)) {
            content = content.split(oldLink).join(newLink);
            fs.writeFileSync(p, content);
            console.log('Updated link in ' + dir + '/' + f);
        }
    });
});
