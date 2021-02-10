if (location.protocol != 'https:' && window.location.href.substring(window.location.protocol.length).toLowerCase().search("macsimum")>=0)
    {
    location.href = 'https:' + window.location.href.substring(window.location.protocol.length);
    }

// console.log(window.location.href.substring(window.location.protocol.length).toLowerCase().search("macsimum")>=0);

