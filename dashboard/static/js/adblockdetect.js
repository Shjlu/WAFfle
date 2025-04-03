
function check(window) {
    
    let options = {
        bait_class: "ad-block text-ads textAd banner_ad",
        bait_style: "width: 1px !important; height: 1px !important; position: absolute !important; left: -10000px !important; top: -1000px !important;",
    };

    var bait = document.createElement('div');
    bait.className = options.bait_class;
    bait.style = options.bait_style;
    bait.innerHTML = "&nbsp;"
    document.body.appendChild(bait);

    window.setTimeout(() => {
        if (!bait || bait.innerHTML.length == 0
        || bait.clientHeight === 0 ||getComputedStyle(bait).display == 'none')
        {
            let event = new Event("adblock_detected");
            document.dispatchEvent(event);
        }
        bait.remove();
    }, 200);

};

window.onload = () => {check(window);setInterval(() => {check(window);}, 30000)};
document.addEventListener("adblock_detected", ()=>{document.write("DETECTED!!!!!!");});
