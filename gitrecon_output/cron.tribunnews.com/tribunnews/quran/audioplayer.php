<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Audio Player - Al Fatihah</title>

<style>
body{
    font-family: Arial, sans-serif;
    background:#f4f4f4;
}

.player {
    width:420px;
    margin:40px auto;
    background:#fff;
    border-radius:10px;
    padding:20px;
    box-shadow:0 2px 10px rgba(0,0,0,0.1);
}

.title{
    font-size:18px;
    font-weight:bold;
    margin-bottom:10px;
}

.controls{
    display:flex;
    align-items:center;
    gap:10px;
}

button{
    background:#d60000;
    color:#fff;
    border:none;
    border-radius:50%;
    width:40px;
    height:40px;
    cursor:pointer;
}

.progress{
    flex:1;
}

input[type=range]{
    width:100%;
}

.time{
    font-size:12px;
    color:#666;
    margin-top:5px;
}
</style>

</head>

<body>

<div class="player">

<div class="title">
Al-Fatihah
</div>

<audio id="audio"></audio>

<div class="controls">

<button id="play">▶</button>

<div class="progress">
<input type="range" id="seek" value="0" min="0" max="100">
</div>

</div>

<div class="time">
<span id="current">0:00</span> /
<span id="duration">0:00</span>
</div>

</div>


<script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>

<script>

const audio = document.getElementById("audio")
const playBtn = document.getElementById("play")
const seek = document.getElementById("seek")

const current = document.getElementById("current")
const duration = document.getElementById("duration")

const src = "https://asset-2.tribunnews.com/tribunnews/alquran/hls/1/chapter.m3u8"

if (Hls.isSupported()) {

    const hls = new Hls()
    hls.loadSource(src)
    hls.attachMedia(audio)

}
else if (audio.canPlayType('application/vnd.apple.mpegurl')) {

    audio.src = src

}

playBtn.onclick = () => {

    if(audio.paused){
        audio.play()
        playBtn.innerHTML = "❚❚"
    }else{
        audio.pause()
        playBtn.innerHTML = "▶"
    }

}

audio.addEventListener("timeupdate", ()=>{

    const percent = (audio.currentTime / audio.duration) * 100
    seek.value = percent

    current.innerHTML = format(audio.currentTime)

})

audio.addEventListener("loadedmetadata", ()=>{

    duration.innerHTML = format(audio.duration)

})

seek.oninput = ()=>{

    const time = (seek.value / 100) * audio.duration
    audio.currentTime = time

}

function format(sec){

    const m = Math.floor(sec/60)
    const s = Math.floor(sec%60)

    return m+":"+(s<10?"0"+s:s)

}

</script>

</body>
</html>