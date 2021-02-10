/*
 countdown.js v2.3.3 http://countdownjs.org
 Copyright (c)2006-2012 Stephen M. McKamey.
 Licensed under The MIT License.
*/
var module,countdown=function(r){function v(a,b){var c=a.getTime();a.setUTCMonth(a.getUTCMonth()+b);return Math.round((a.getTime()-c)/864E5)}function t(a){var b=a.getTime(),c=new Date(b);c.setUTCMonth(a.getUTCMonth()+1);return Math.round((c.getTime()-b)/864E5)}function h(a,b){return a+" "+(1===a?p[b]:q[b])}function n(){}function l(a,b,c,g,f,d){0<=a[c]&&(b+=a[c],delete a[c]);b/=f;if(1>=b+1)return 0;if(0<=a[g]){a[g]=+(a[g]+b).toFixed(d);switch(g){case "seconds":if(60!==a.seconds||isNaN(a.minutes))break;
a.minutes++;a.seconds=0;case "minutes":if(60!==a.minutes||isNaN(a.hours))break;a.hours++;a.minutes=0;case "hours":if(24!==a.hours||isNaN(a.days))break;a.days++;a.hours=0;case "days":if(7!==a.days||isNaN(a.weeks))break;a.weeks++;a.days=0;case "weeks":if(a.weeks!==t(a.refMonth)/7||isNaN(a.months))break;a.months++;a.weeks=0;case "months":if(12!==a.months||isNaN(a.years))break;a.years++;a.months=0;case "years":if(10!==a.years||isNaN(a.decades))break;a.decades++;a.years=0;case "decades":if(10!==a.decades||
isNaN(a.centuries))break;a.centuries++;a.decades=0;case "centuries":if(10!==a.centuries||isNaN(a.millennia))break;a.millennia++;a.centuries=0}return 0}return b}function w(a,b,c,g,f,d){a.start=b;a.end=c;a.units=g;a.value=c.getTime()-b.getTime();if(0>a.value){var h=c;c=b;b=h}a.refMonth=new Date(b.getFullYear(),b.getMonth(),15);try{a.millennia=0;a.centuries=0;a.decades=0;a.years=c.getUTCFullYear()-b.getUTCFullYear();a.months=c.getUTCMonth()-b.getUTCMonth();a.weeks=0;a.days=c.getUTCDate()-b.getUTCDate();
a.hours=c.getUTCHours()-b.getUTCHours();a.minutes=c.getUTCMinutes()-b.getUTCMinutes();a.seconds=c.getUTCSeconds()-b.getUTCSeconds();a.milliseconds=c.getUTCMilliseconds()-b.getUTCMilliseconds();var k;0>a.milliseconds?(k=s(-a.milliseconds/1E3),a.seconds-=k,a.milliseconds+=1E3*k):1E3<=a.milliseconds&&(a.seconds+=m(a.milliseconds/1E3),a.milliseconds%=1E3);0>a.seconds?(k=s(-a.seconds/60),a.minutes-=k,a.seconds+=60*k):60<=a.seconds&&(a.minutes+=m(a.seconds/60),a.seconds%=60);0>a.minutes?(k=s(-a.minutes/
60),a.hours-=k,a.minutes+=60*k):60<=a.minutes&&(a.hours+=m(a.minutes/60),a.minutes%=60);0>a.hours?(k=s(-a.hours/24),a.days-=k,a.hours+=24*k):24<=a.hours&&(a.days+=m(a.hours/24),a.hours%=24);for(;0>a.days;)a.months--,a.days+=v(a.refMonth,1);7<=a.days&&(a.weeks+=m(a.days/7),a.days%=7);0>a.months?(k=s(-a.months/12),a.years-=k,a.months+=12*k):12<=a.months&&(a.years+=m(a.months/12),a.months%=12);10<=a.years&&(a.decades+=m(a.years/10),a.years%=10,10<=a.decades&&(a.centuries+=m(a.decades/10),a.decades%=
10,10<=a.centuries&&(a.millennia+=m(a.centuries/10),a.centuries%=10)));b=0;!(g&1024)||b>=f?(a.centuries+=10*a.millennia,delete a.millennia):a.millennia&&b++;!(g&512)||b>=f?(a.decades+=10*a.centuries,delete a.centuries):a.centuries&&b++;!(g&256)||b>=f?(a.years+=10*a.decades,delete a.decades):a.decades&&b++;!(g&128)||b>=f?(a.months+=12*a.years,delete a.years):a.years&&b++;!(g&64)||b>=f?(a.months&&(a.days+=v(a.refMonth,a.months)),delete a.months,7<=a.days&&(a.weeks+=m(a.days/7),a.days%=7)):a.months&&
b++;!(g&32)||b>=f?(a.days+=7*a.weeks,delete a.weeks):a.weeks&&b++;!(g&16)||b>=f?(a.hours+=24*a.days,delete a.days):a.days&&b++;!(g&8)||b>=f?(a.minutes+=60*a.hours,delete a.hours):a.hours&&b++;!(g&4)||b>=f?(a.seconds+=60*a.minutes,delete a.minutes):a.minutes&&b++;!(g&2)||b>=f?(a.milliseconds+=1E3*a.seconds,delete a.seconds):a.seconds&&b++;if(!(g&1)||b>=f){var e=l(a,0,"milliseconds","seconds",1E3,d);if(e&&(e=l(a,e,"seconds","minutes",60,d))&&(e=l(a,e,"minutes","hours",60,d))&&(e=l(a,e,"hours","days",
24,d))&&(e=l(a,e,"days","weeks",7,d))&&(e=l(a,e,"weeks","months",t(a.refMonth)/7,d))){g=e;var n,p=a.refMonth,q=p.getTime(),r=new Date(q);r.setUTCFullYear(p.getUTCFullYear()+1);n=Math.round((r.getTime()-q)/864E5);if(e=l(a,g,"months","years",n/t(a.refMonth),d))if(e=l(a,e,"years","decades",10,d))if(e=l(a,e,"decades","centuries",10,d))if(e=l(a,e,"centuries","millennia",10,d))throw Error("Fractional unit overflow");}}}finally{delete a.refMonth}return a}function d(a,b,c,d,f){var h;c=+c||222;d=0<d?d:NaN;
f=0<f?20>f?Math.round(f):20:0;"function"===typeof a?(h=a,a=null):a instanceof Date||(a=null!==a&&isFinite(a)?new Date(a):null);"function"===typeof b?(h=b,b=null):b instanceof Date||(b=null!==b&&isFinite(b)?new Date(b):null);if(!a&&!b)return new n;if(!h)return w(new n,a||new Date,b||new Date,c,d,f);var l=c&1?1E3/30:c&2?1E3:c&4?6E4:c&8?36E5:c&16?864E5:6048E5,k,e=function(){h(w(new n,a||new Date,b||new Date,c,d,f),k)};e();return k=setInterval(e,l)}var s=Math.ceil,m=Math.floor,p,q,u;n.prototype.toString=
function(){var a=u(this),b=a.length;if(!b)return"";1<b&&(a[b-1]="and "+a[b-1]);return a.join(", ")};n.prototype.toHTML=function(a){a=a||"span";var b=u(this),c=b.length;if(!c)return"";for(var d=0;d<c;d++)b[d]="\x3c"+a+"\x3e"+b[d]+"\x3c/"+a+"\x3e";--c&&(b[c]="and "+b[c]);return b.join(", ")};u=function(a){var b=[],c=a.millennia;c&&b.push(h(c,10));(c=a.centuries)&&b.push(h(c,9));(c=a.decades)&&b.push(h(c,8));(c=a.years)&&b.push(h(c,7));(c=a.months)&&b.push(h(c,6));(c=a.weeks)&&b.push(h(c,5));(c=a.days)&&
b.push(h(c,4));(c=a.hours)&&b.push(h(c,3));(c=a.minutes)&&b.push(h(c,2));(c=a.seconds)&&b.push(h(c,1));(c=a.milliseconds)&&b.push(h(c,0));return b};d.MILLISECONDS=1;d.SECONDS=2;d.MINUTES=4;d.HOURS=8;d.DAYS=16;d.WEEKS=32;d.MONTHS=64;d.YEARS=128;d.DECADES=256;d.CENTURIES=512;d.MILLENNIA=1024;d.DEFAULTS=222;d.ALL=2047;d.setLabels=function(a,b){a=a||[];a.split&&(a=a.split("|"));b=b||[];b.split&&(b=b.split("|"));for(var c=0;10>=c;c++)p[c]=a[c]||p[c],q[c]=b[c]||q[c]};(d.resetLabels=function(){p="millisecond second minute hour day week month year decade century millennium".split(" ");
q="milliseconds seconds minutes hours days weeks months years decades centuries millennia".split(" ")})();r&&r.exports&&(r.exports=d);return d}(module);/*!
 * segment-display.js
 *
 * Copyright 2012, Rüdiger Appel
 * http://www.3quarks.com
 * Published under Creative Commons 3.0 License.
 *
 * Date: 2012-02-14
 * Version: 1.0.0
 * 
 * Dokumentation: http://www.3quarks.com/de/Segmentanzeige
 * Documentation: http://www.3quarks.com/en/SegmentDisplay
 */

// Segment display types
SegmentDisplay.SevenSegment    = 7;
SegmentDisplay.FourteenSegment = 14;
SegmentDisplay.SixteenSegment  = 16;

// Segment corner types
SegmentDisplay.SymmetricCorner = 0;
SegmentDisplay.SquaredCorner   = 1;
SegmentDisplay.RoundedCorner   = 2;


function SegmentDisplay(displayId) {
  this.displayId       = displayId;
  this.pattern         = '##:##:##';
  this.value           = '12:34:56';
  this.digitHeight     = 20;
  this.digitWidth      = 10;
  this.digitDistance   = 2.5;
  this.displayAngle    = 12;
  this.segmentWidth    = 2.5;
  this.segmentDistance = 0.2;
  this.segmentCount    = SegmentDisplay.SevenSegment;
  this.cornerType      = SegmentDisplay.RoundedCorner;
  this.colorOn         = 'rgb(233, 93, 15)';
  this.colorOff        = 'rgb(75, 30, 5)';
};

SegmentDisplay.prototype.setValue = function(value) {
  this.value = value;
  this.draw();
};

SegmentDisplay.prototype.draw = function() {
  var display = document.getElementById(this.displayId);
  if (display) {
    var context = display.getContext('2d');
    if (context) {
      // clear canvas
      context.clearRect(0, 0, display.width, display.height);
      
      // compute and check display width
      var width = 0;
      var first = true;
      if (this.pattern) {
        for (var i = 0; i < this.pattern.length; i++) {
          var c = this.pattern.charAt(i).toLowerCase();
          if (c == '#') {
            width += this.digitWidth;
          } else if (c == '.' || c == ':') {
            width += this.segmentWidth;
          } else if (c != ' ') {
            return;
          }
          width += first ? 0 : this.digitDistance;
          first = false;
        }
      }
      if (width <= 0) {
        return;
      }
      
      // compute skew factor
      var angle = -1.0 * Math.max(-45.0, Math.min(45.0, this.displayAngle));
      var skew  = Math.tan((angle * Math.PI) / 180.0);
      
      // compute scale factor
      var scale = Math.min(display.width / (width + Math.abs(skew * this.digitHeight)), display.height / this.digitHeight);
      
      // compute display offset
      var offsetX = (display.width - (width + skew * this.digitHeight) * scale) / 2.0;
      var offsetY = (display.height - this.digitHeight * scale) / 2.0;
      
      // context transformation
      context.save();
      context.translate(offsetX, offsetY);
      context.scale(scale, scale);
      context.transform(1, 0, skew, 1, 0, 0);

      // draw segments
      var xPos = 0;
      var size = (this.value) ? this.value.length : 0;
      for (var i = 0; i < this.pattern.length; i++) {
        var mask  = this.pattern.charAt(i);
        var value = (i < size) ? this.value.charAt(i).toLowerCase() : ' ';
        xPos += this.drawDigit(context, xPos, mask, value);
      }

      // finish drawing
      context.restore();
    }
  }
};

SegmentDisplay.prototype.drawDigit = function(context, xPos, mask, c) {
  switch (mask) {
    case '#':
      var r = Math.sqrt(this.segmentWidth * this.segmentWidth / 2.0);
      var d = Math.sqrt(this.segmentDistance * this.segmentDistance / 2.0);
      var e = d / 2.0; 
      var f = (this.segmentWidth - d) * Math.sin((45.0 * Math.PI) / 180.0);
      var g = f / 2.0;
      var h = (this.digitHeight - 3.0 * this.segmentWidth) / 2.0;
      var w = (this.digitWidth - 3.0 * this.segmentWidth) / 2.0;
      var s = this.segmentWidth / 2.0;
      var t = this.digitWidth / 2.0;

      // draw segment a (a1 and a2 for 16 segments)
      if (this.segmentCount == 16) {
        var x = xPos;
        var y = 0;
        context.fillStyle = this.getSegmentColor(c, null, '02356789abcdefgiopqrstz@%');
        context.beginPath();
        switch (this.cornerType) {
          case SegmentDisplay.SymmetricCorner:
            context.moveTo(x + s + d, y + s);
            context.lineTo(x + this.segmentWidth + d, y);
            break;
          case SegmentDisplay.SquaredCorner:
            context.moveTo(x + s + e, y + s - e);
            context.lineTo(x + this.segmentWidth, y);
            break;
          default:
            context.moveTo(x + this.segmentWidth - f, y + this.segmentWidth - f - d);
            context.quadraticCurveTo(x + this.segmentWidth - g, y, x + this.segmentWidth, y);
        }
        context.lineTo(x + t - d - s, y);
        context.lineTo(x + t - d, y + s);
        context.lineTo(x + t - d - s, y + this.segmentWidth);
        context.lineTo(x + this.segmentWidth + d, y + this.segmentWidth);
        context.fill();
        
        var x = xPos;
        var y = 0;
        context.fillStyle = this.getSegmentColor(c, null, '02356789abcdefgiopqrstz@');
        context.beginPath();
        context.moveTo(x + this.digitWidth - this.segmentWidth - d, y + this.segmentWidth);
        context.lineTo(x + t + d + s, y + this.segmentWidth);
        context.lineTo(x + t + d, y + s);
        context.lineTo(x + t + d + s, y);
        switch (this.cornerType) {
          case SegmentDisplay.SymmetricCorner:
            context.lineTo(x + this.digitWidth - this.segmentWidth - d, y);
            context.lineTo(x + this.digitWidth - s - d, y + s);
            break;
          case SegmentDisplay.SquaredCorner:
            context.lineTo(x + this.digitWidth - this.segmentWidth, y);
            context.lineTo(x + this.digitWidth - s - e, y + s - e);
            break;
          default:
            context.lineTo(x + this.digitWidth - this.segmentWidth, y);
            context.quadraticCurveTo(x + this.digitWidth - this.segmentWidth + g, y, x + this.digitWidth - this.segmentWidth + f, y + this.segmentWidth - f - d);
        }
        context.fill();
        
      } else {
        var x = xPos;
        var y = 0;
        context.fillStyle = this.getSegmentColor(c, '02356789acefp', '02356789abcdefgiopqrstz@');
        context.beginPath();
        switch (this.cornerType) {
          case SegmentDisplay.SymmetricCorner:
            context.moveTo(x + s + d, y + s);
            context.lineTo(x + this.segmentWidth + d, y);
            context.lineTo(x + this.digitWidth - this.segmentWidth - d, y);
            context.lineTo(x + this.digitWidth - s - d, y + s);
            break;
          case SegmentDisplay.SquaredCorner:
            context.moveTo(x + s + e, y + s - e);
            context.lineTo(x + this.segmentWidth, y);
            context.lineTo(x + this.digitWidth - this.segmentWidth, y);
            context.lineTo(x + this.digitWidth - s - e, y + s - e);
            break;
          default:
            context.moveTo(x + this.segmentWidth - f, y + this.segmentWidth - f - d);
            context.quadraticCurveTo(x + this.segmentWidth - g, y, x + this.segmentWidth, y);
            context.lineTo(x + this.digitWidth - this.segmentWidth, y);
            context.quadraticCurveTo(x + this.digitWidth - this.segmentWidth + g, y, x + this.digitWidth - this.segmentWidth + f, y + this.segmentWidth - f - d);
        }
        context.lineTo(x + this.digitWidth - this.segmentWidth - d, y + this.segmentWidth);
        context.lineTo(x + this.segmentWidth + d, y + this.segmentWidth);
        context.fill();
      }
      
      // draw segment b
      x = xPos + this.digitWidth - this.segmentWidth;
      y = 0;
      context.fillStyle = this.getSegmentColor(c, '01234789adhpy', '01234789abdhjmnopqruwy');
      context.beginPath();
      switch (this.cornerType) {
        case SegmentDisplay.SymmetricCorner:
          context.moveTo(x + s, y + s + d);
          context.lineTo(x + this.segmentWidth, y + this.segmentWidth + d);
          break;
        case SegmentDisplay.SquaredCorner:
          context.moveTo(x + s + e, y + s + e);
          context.lineTo(x + this.segmentWidth, y + this.segmentWidth);
          break;
        default:
          context.moveTo(x + f + d, y + this.segmentWidth - f);
          context.quadraticCurveTo(x + this.segmentWidth, y + this.segmentWidth - g, x + this.segmentWidth, y + this.segmentWidth);
      }
      context.lineTo(x + this.segmentWidth, y + h + this.segmentWidth - d);
      context.lineTo(x + s, y + h + this.segmentWidth + s - d);
      context.lineTo(x, y + h + this.segmentWidth - d);
      context.lineTo(x, y + this.segmentWidth + d);
      context.fill();
      
      // draw segment c
      x = xPos + this.digitWidth - this.segmentWidth;
      y = h + this.segmentWidth;
      context.fillStyle = this.getSegmentColor(c, '013456789abdhnouy', '01346789abdghjmnoqsuw@', '%');
      context.beginPath();
      context.moveTo(x, y + this.segmentWidth + d);
      context.lineTo(x + s, y + s + d);
      context.lineTo(x + this.segmentWidth, y + this.segmentWidth + d);
      context.lineTo(x + this.segmentWidth, y + h + this.segmentWidth - d);
      switch (this.cornerType) {
        case SegmentDisplay.SymmetricCorner:
          context.lineTo(x + s, y + h + this.segmentWidth + s - d);
          context.lineTo(x, y + h + this.segmentWidth - d);
          break;
        case SegmentDisplay.SquaredCorner:
          context.lineTo(x + s + e, y + h + this.segmentWidth + s - e);
          context.lineTo(x, y + h + this.segmentWidth - d);
          break;
        default:
          context.quadraticCurveTo(x + this.segmentWidth, y + h + this.segmentWidth + g, x + f + d, y + h + this.segmentWidth + f); //
          context.lineTo(x, y + h + this.segmentWidth - d);
      }
      context.fill();
      
      // draw segment d (d1 and d2 for 16 segments)
      if (this.segmentCount == 16) {
        x = xPos;
        y = this.digitHeight - this.segmentWidth;
        context.fillStyle = this.getSegmentColor(c, null, '0235689bcdegijloqsuz_=@');
        context.beginPath();
        context.moveTo(x + this.segmentWidth + d, y);
        context.lineTo(x + t - d - s, y);
        context.lineTo(x + t - d, y + s);
        context.lineTo(x + t - d - s, y + this.segmentWidth);
        switch (this.cornerType) {
          case SegmentDisplay.SymmetricCorner:
            context.lineTo(x + this.segmentWidth + d, y + this.segmentWidth);
            context.lineTo(x + s + d, y + s);
            break;
          case SegmentDisplay.SquaredCorner:
            context.lineTo(x + this.segmentWidth, y + this.segmentWidth);
            context.lineTo(x + s + e, y + s + e);
            break;
          default:
            context.lineTo(x + this.segmentWidth, y + this.segmentWidth);
            context.quadraticCurveTo(x + this.segmentWidth - g, y + this.segmentWidth, x + this.segmentWidth - f, y + f + d);
            context.lineTo(x + this.segmentWidth - f, y + f + d);
        }
        context.fill();

        x = xPos;
        y = this.digitHeight - this.segmentWidth;
        context.fillStyle = this.getSegmentColor(c, null, '0235689bcdegijloqsuz_=@', '%');
        context.beginPath();
        context.moveTo(x + t + d + s, y + this.segmentWidth);
        context.lineTo(x + t + d, y + s);
        context.lineTo(x + t + d + s, y);
        context.lineTo(x + this.digitWidth - this.segmentWidth - d, y);
        switch (this.cornerType) {
          case SegmentDisplay.SymmetricCorner:
            context.lineTo(x + this.digitWidth - s - d, y + s);
            context.lineTo(x + this.digitWidth - this.segmentWidth - d, y + this.segmentWidth);
            break;
          case SegmentDisplay.SquaredCorner:
            context.lineTo(x + this.digitWidth - s - e, y + s + e);
            context.lineTo(x + this.digitWidth - this.segmentWidth, y + this.segmentWidth);
            break;
          default:
            context.lineTo(x + this.digitWidth - this.segmentWidth + f, y + f + d);
            context.quadraticCurveTo(x + this.digitWidth - this.segmentWidth + g, y + this.segmentWidth, x + this.digitWidth - this.segmentWidth, y + this.segmentWidth);
        }
        context.fill();
      }
      else {
        x = xPos;
        y = this.digitHeight - this.segmentWidth;
        context.fillStyle = this.getSegmentColor(c, '0235689bcdelotuy_', '0235689bcdegijloqsuz_=@');
        context.beginPath();
        context.moveTo(x + this.segmentWidth + d, y);
        context.lineTo(x + this.digitWidth - this.segmentWidth - d, y);
        switch (this.cornerType) {
          case SegmentDisplay.SymmetricCorner:
            context.lineTo(x + this.digitWidth - s - d, y + s);
            context.lineTo(x + this.digitWidth - this.segmentWidth - d, y + this.segmentWidth);
            context.lineTo(x + this.segmentWidth + d, y + this.segmentWidth);
            context.lineTo(x + s + d, y + s);
            break;
          case SegmentDisplay.SquaredCorner:
            context.lineTo(x + this.digitWidth - s - e, y + s + e);
            context.lineTo(x + this.digitWidth - this.segmentWidth, y + this.segmentWidth);
            context.lineTo(x + this.segmentWidth, y + this.segmentWidth);
            context.lineTo(x + s + e, y + s + e);
            break;
          default:
            context.lineTo(x + this.digitWidth - this.segmentWidth + f, y + f + d);
            context.quadraticCurveTo(x + this.digitWidth - this.segmentWidth + g, y + this.segmentWidth, x + this.digitWidth - this.segmentWidth, y + this.segmentWidth);
            context.lineTo(x + this.segmentWidth, y + this.segmentWidth);
            context.quadraticCurveTo(x + this.segmentWidth - g, y + this.segmentWidth, x + this.segmentWidth - f, y + f + d);
            context.lineTo(x + this.segmentWidth - f, y + f + d);
        }
        context.fill();
      }
      
      // draw segment e
      x = xPos;
      y = h + this.segmentWidth;
      context.fillStyle = this.getSegmentColor(c, '0268abcdefhlnoprtu', '0268acefghjklmnopqruvw@');
      context.beginPath();
      context.moveTo(x, y + this.segmentWidth + d);
      context.lineTo(x + s, y + s + d);
      context.lineTo(x + this.segmentWidth, y + this.segmentWidth + d);
      context.lineTo(x + this.segmentWidth, y + h + this.segmentWidth - d);
      switch (this.cornerType) {
        case SegmentDisplay.SymmetricCorner:
          context.lineTo(x + s, y + h + this.segmentWidth + s - d);
          context.lineTo(x, y + h + this.segmentWidth - d);
          break;
        case SegmentDisplay.SquaredCorner:
          context.lineTo(x + s - e, y + h + this.segmentWidth + s - d + e);
          context.lineTo(x, y + h + this.segmentWidth);
          break;
        default:
          context.lineTo(x + this.segmentWidth - f - d, y + h + this.segmentWidth + f); 
          context.quadraticCurveTo(x, y + h + this.segmentWidth + g, x, y + h + this.segmentWidth);
      }
      context.fill();
      
      // draw segment f
      x = xPos;
      y = 0;
      context.fillStyle = this.getSegmentColor(c, '045689abcefhlpty', '045689acefghklmnopqrsuvwy@', '%');
      context.beginPath();
      context.moveTo(x + this.segmentWidth, y + this.segmentWidth + d);
      context.lineTo(x + this.segmentWidth, y + h + this.segmentWidth - d);
      context.lineTo(x + s, y + h + this.segmentWidth + s - d);
      context.lineTo(x, y + h + this.segmentWidth - d);
      switch (this.cornerType) {
        case SegmentDisplay.SymmetricCorner:
          context.lineTo(x, y + this.segmentWidth + d);
          context.lineTo(x + s, y + s + d);
          break;
        case SegmentDisplay.SquaredCorner:
          context.lineTo(x, y + this.segmentWidth);
          context.lineTo(x + s - e, y + s + e);
          break;
        default:
          context.lineTo(x, y + this.segmentWidth);
          context.quadraticCurveTo(x, y + this.segmentWidth - g, x + this.segmentWidth - f - d, y + this.segmentWidth - f); 
          context.lineTo(x + this.segmentWidth - f - d, y + this.segmentWidth - f); 
      }
      context.fill();

      // draw segment g for 7 segments
      if (this.segmentCount == 7) {
        x = xPos;
        y = (this.digitHeight - this.segmentWidth) / 2.0;
        context.fillStyle = this.getSegmentColor(c, '2345689abdefhnoprty-=');
        context.beginPath();
        context.moveTo(x + s + d, y + s);
        context.lineTo(x + this.segmentWidth + d, y);
        context.lineTo(x + this.digitWidth - this.segmentWidth - d, y);
        context.lineTo(x + this.digitWidth - s - d, y + s);
        context.lineTo(x + this.digitWidth - this.segmentWidth - d, y + this.segmentWidth);
        context.lineTo(x + this.segmentWidth + d, y + this.segmentWidth);
        context.fill();
      }
            
      // draw inner segments for the fourteen- and sixteen-segment-display
      if (this.segmentCount != 7) {
        // draw segment g1
        x = xPos;
        y = (this.digitHeight - this.segmentWidth) / 2.0;
        context.fillStyle = this.getSegmentColor(c, null, '2345689aefhkprsy-+*=', '%');
        context.beginPath();
        context.moveTo(x + s + d, y + s);
        context.lineTo(x + this.segmentWidth + d, y);
        context.lineTo(x + t - d - s, y);
        context.lineTo(x + t - d, y + s);
        context.lineTo(x + t - d - s, y + this.segmentWidth);
        context.lineTo(x + this.segmentWidth + d, y + this.segmentWidth);
        context.fill();
        
        // draw segment g2
        x = xPos;
        y = (this.digitHeight - this.segmentWidth) / 2.0;
        context.fillStyle = this.getSegmentColor(c, null, '234689abefghprsy-+*=@', '%');
        context.beginPath();
        context.moveTo(x + t + d, y + s);
        context.lineTo(x + t + d + s, y);
        context.lineTo(x + this.digitWidth - this.segmentWidth - d, y);
        context.lineTo(x + this.digitWidth - s - d, y + s);
        context.lineTo(x + this.digitWidth - this.segmentWidth - d, y + this.segmentWidth);
        context.lineTo(x + t + d + s, y + this.segmentWidth);
        context.fill();
        
        // draw segment j 
        x = xPos + t - s;
        y = 0;
        context.fillStyle = this.getSegmentColor(c, null, 'bdit+*', '%');
        context.beginPath();
        if (this.segmentCount == 14) {
          context.moveTo(x, y + this.segmentWidth + this.segmentDistance);
          context.lineTo(x + this.segmentWidth, y + this.segmentWidth + this.segmentDistance);
        } else {
          context.moveTo(x, y + this.segmentWidth + d);
          context.lineTo(x + s, y + s + d);
          context.lineTo(x + this.segmentWidth, y + this.segmentWidth + d);
        }
        context.lineTo(x + this.segmentWidth, y + h + this.segmentWidth - d);
        context.lineTo(x + s, y + h + this.segmentWidth + s - d);
        context.lineTo(x, y + h + this.segmentWidth - d);
        context.fill();
        
        // draw segment m
        x = xPos + t - s;
        y = this.digitHeight;
        context.fillStyle = this.getSegmentColor(c, null, 'bdity+*@', '%');
        context.beginPath();
        if (this.segmentCount == 14) {
          context.moveTo(x, y - this.segmentWidth - this.segmentDistance);
          context.lineTo(x + this.segmentWidth, y - this.segmentWidth - this.segmentDistance);
        } else {
          context.moveTo(x, y - this.segmentWidth - d);
          context.lineTo(x + s, y - s - d);
          context.lineTo(x + this.segmentWidth, y - this.segmentWidth - d);
        }
        context.lineTo(x + this.segmentWidth, y - h - this.segmentWidth + d);
        context.lineTo(x + s, y - h - this.segmentWidth - s + d);
        context.lineTo(x, y - h - this.segmentWidth + d);
        context.fill();
        
        // draw segment h
        x = xPos + this.segmentWidth;
        y = this.segmentWidth;
        context.fillStyle = this.getSegmentColor(c, null, 'mnx\\*');
        context.beginPath();
        context.moveTo(x + this.segmentDistance, y + this.segmentDistance);
        context.lineTo(x + this.segmentDistance + r, y + this.segmentDistance);
        context.lineTo(x + w - this.segmentDistance , y + h - this.segmentDistance - r);
        context.lineTo(x + w - this.segmentDistance , y + h - this.segmentDistance);
        context.lineTo(x + w - this.segmentDistance - r , y + h - this.segmentDistance);
        context.lineTo(x + this.segmentDistance, y + this.segmentDistance + r);
        context.fill();
        
        // draw segment k
        x = xPos + w + 2.0 * this.segmentWidth;
        y = this.segmentWidth;
        context.fillStyle = this.getSegmentColor(c, null, '0kmvxz/*', '%');
        context.beginPath();
        context.moveTo(x + w - this.segmentDistance, y + this.segmentDistance);
        context.lineTo(x + w - this.segmentDistance, y + this.segmentDistance + r);
        context.lineTo(x + this.segmentDistance + r, y + h - this.segmentDistance);
        context.lineTo(x + this.segmentDistance, y + h - this.segmentDistance);
        context.lineTo(x + this.segmentDistance, y + h - this.segmentDistance - r);
        context.lineTo(x + w - this.segmentDistance - r, y + this.segmentDistance);
        context.fill();
        
        // draw segment l
        x = xPos + w + 2.0 * this.segmentWidth;
        y = h + 2.0 * this.segmentWidth;
        context.fillStyle = this.getSegmentColor(c, null, '5knqrwx\\*');
        context.beginPath();
        context.moveTo(x + this.segmentDistance, y + this.segmentDistance);
        context.lineTo(x + this.segmentDistance + r, y + this.segmentDistance);
        context.lineTo(x + w - this.segmentDistance , y + h - this.segmentDistance - r);
        context.lineTo(x + w - this.segmentDistance , y + h - this.segmentDistance);
        context.lineTo(x + w - this.segmentDistance - r , y + h - this.segmentDistance);
        context.lineTo(x + this.segmentDistance, y + this.segmentDistance + r);
        context.fill();
        
        // draw segment n
        x = xPos + this.segmentWidth;
        y = h + 2.0 * this.segmentWidth;
        context.fillStyle = this.getSegmentColor(c, null, '0vwxz/*', '%');
        context.beginPath();
        context.moveTo(x + w - this.segmentDistance, y + this.segmentDistance);
        context.lineTo(x + w - this.segmentDistance, y + this.segmentDistance + r);
        context.lineTo(x + this.segmentDistance + r, y + h - this.segmentDistance);
        context.lineTo(x + this.segmentDistance, y + h - this.segmentDistance);
        context.lineTo(x + this.segmentDistance, y + h - this.segmentDistance - r);
        context.lineTo(x + w - this.segmentDistance - r, y + this.segmentDistance);
        context.fill();
      }
      
      return this.digitDistance + this.digitWidth;
      
    case '.':
      context.fillStyle = (c == '#') || (c == '.') ? this.colorOn : this.colorOff;
      this.drawPoint(context, xPos, this.digitHeight - this.segmentWidth, this.segmentWidth);
      return this.digitDistance + this.segmentWidth;
      
    case ':':
      context.fillStyle = (c == '#') || (c == ':') ? this.colorOn : this.colorOff;
      var y = (this.digitHeight - this.segmentWidth) / 2.0 - this.segmentWidth;
      this.drawPoint(context, xPos, y, this.segmentWidth);
      this.drawPoint(context, xPos, y + 2.0 * this.segmentWidth, this.segmentWidth);
      return this.digitDistance + this.segmentWidth;
      
    default:
      return this.digitDistance;    
  }
};

SegmentDisplay.prototype.drawPoint = function(context, x1, y1, size) {
  var x2 = x1 + size;
  var y2 = y1 + size;
  var d  = size / 4.0;
  
  context.beginPath();
  context.moveTo(x2 - d, y1);
  context.quadraticCurveTo(x2, y1, x2, y1 + d);
  context.lineTo(x2, y2 - d);
  context.quadraticCurveTo(x2, y2, x2 - d, y2);
  context.lineTo(x1 + d, y2);
  context.quadraticCurveTo(x1, y2, x1, y2 - d);
  context.lineTo(x1, y1 + d);
  context.quadraticCurveTo(x1, y1, x1 + d, y1);
  context.fill();
}; 

SegmentDisplay.prototype.getSegmentColor = function(c, charSet7, charSet14, charSet16) {
  if (c == '#') {
    return this.colorOn;
  } else {
    switch (this.segmentCount) {
      case 7:  return (charSet7.indexOf(c) == -1) ? this.colorOff : this.colorOn;
      case 14: return (charSet14.indexOf(c) == -1) ? this.colorOff : this.colorOn;
      case 16: var pattern = charSet14 + (charSet16 === undefined ? '' : charSet16);
               return (pattern.indexOf(c) == -1) ? this.colorOff : this.colorOn;
      default: return this.colorOff;
    }
  }
};




/*
 Name: pangu.js (paranoid_spacing.js)
 Version: 1.7.2
 URL: https://github.com/gibuloto/paranoid-auto-spacing
 Author: Vinta
 License: MIT License
 Description: Insert a white space between full-width characters (Chinese, Japanese, etc.) and half-width alphanumeric characters
*/

function insertSpace(text) {
    /*
     英文、數字、符號 ([a-z0-9~!@#&;=_\$\%\^\*\-\+\,\.\/(\\)\?\:\'\"\[\]\(\)])
     中文 ([\u4E00-\u9FFF])
     日文 ([\u3040-\u30FF])
     http://www.diybl.com/course/6_system/linux/Linuxjs/20090426/165435.html
     */

    // 中文在前
    text = text.replace(/([\u4e00-\u9fa5\u3040-\u30FF])([a-z0-9@&=_\[\$\%\^\*\-\+\(\/\\])/ig, '$1 $2');

    // 中文在後
    text = text.replace(/([a-z0-9!~&;=_\]\,\.\:\?\$\%\^\*\-\+\)\/\\])([\u4e00-\u9fa5\u3040-\u30FF])/ig, '$1 $2');

    // 字"字"字 >> 字 "字" 字
    text = text.replace(/([\u4e00-\u9fa5\u3040-\u30FF])(\"|\'(\S+))/ig, '$1 $2');
    text = text.replace(/((\S+)\'|\")([\u4e00-\u9fa5\u3040-\u30FF])/ig, '$1 $3'); // $2 是 (\S+)

    return text;
}