<?php
date_default_timezone_set('Asia/Jakarta');
set_time_limit(0);
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT ."config/config.php";
include DOC_ROOT ."lib/Utils.php";
include DOC_ROOT."lib/Opensearch.php";

$chapter_alias = isset($_SERVER["argv"][1])?$_SERVER["argv"][1]:0;
if(isset($_GET['surah_id'])){
	$chapter_alias = $_GET['surah_id'];
}

if(!empty($chapter_alias)){
	$urlJson = "https://asset-2.tribunnews.com/tribunnews/alquran/json/surah/".$chapter_alias.".json";

	$user_agents = [
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
			"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
		];
	$random_user_agent = $user_agents[array_rand($user_agents)];

	$options = array(
	  'http'=>array(
		'method'=>"GET",
		'header'=>"Accept-language: en\r\n" .
				  "User-Agent: ".$random_user_agent."\r\n",
				  "timeout" => 1
	  )
	);

	$context = stream_context_create($options);
	$results = @file_get_contents($urlJson, false, $context);
	
	$arrAlQuranCache = array();
	if($results != false){
		$arrAlQuranCache = json_decode($results, TRUE);
	}

	if(is_countable($arrAlQuranCache) && count($arrAlQuranCache) > 0){
		$surahInfo = $arrAlQuranCache['surah'] ?? array();
		$ayahList = $arrAlQuranCache['surah']['ayah'] ?? array();
	} else {
		$index = "quran";

		$opensearchDev = new Opensearch();
		$opensearchDev->init(OS_DEV_URL,OS_DEV_USERNAME,OS_DEV_PASSWORD,true);

		$opensearchTBO = new Opensearch();
		$opensearchTBO->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);


		$condition = array(
			'bool' => array(
				'must' => array(
					array(
						'term' => array(
							'chapter_alias' => $chapter_alias
						)
					)
				)
			)
		);

		$fields = array(
			'chapter_id',
			'chapter_name_latin_id',
			'chapter_translation_id',
			'chapter_type_id',
			'chapter_total_verses',
			'surah_name',
			'ayah_id',
			'verse_key',
			'ayah_text',
			'ayah_plain',
			'ayah_transliteration_en',
			'ayah_translation_en',
			'ayah_translation_id',
			'ayah_tafsir_short_id',
			'ayah_tafsir_long_id',
			'ayah_audio_primary',
			'juz',
			'ruku',
			'manzil'
		);


		$sort = array(
			array(
				'ayah_id' => array(
					'order' => 'asc'
				)
			)
		);

		$response = $opensearchTBO->find('quran', $condition, $fields, $sort, 0, 400);
		
		$surahInfo = array();
		$ayahList = array();
		$errorMessage = '';
		
		if (isset($response['status']) && $response['status'] == 1 && !empty($response['data'])) {
			$noAyat = 1;

			foreach ($response['data'] as $row) {
				$src = isset($row['_source']) ? $row['_source'] : array();

				if (empty($surahInfo)) {
					$surahInfo = array(
						'chapter_id'             => isset($src['chapter_id']) ? $src['chapter_id'] : '',
						'chapter_name_latin_id'  => isset($src['chapter_name_latin_id']) ? $src['chapter_name_latin_id'] : '',
						'chapter_translation_id' => isset($src['chapter_translation_id']) ? $src['chapter_translation_id'] : '',
						'chapter_type_id'        => isset($src['chapter_type_id']) ? $src['chapter_type_id'] : '',
						'chapter_total_verses'   => isset($src['chapter_total_verses']) ? $src['chapter_total_verses'] : 0,
						'surah_name'             => isset($src['surah_name']) ? $src['surah_name'] : '',
						'juz'                    => isset($src['juz']) ? $src['juz'] : ''
					);
				}

				$ayahList[] = array(
					'no_ayat'              		=> $noAyat,
					'verse_key'            		=> isset($src['verse_key']) ? $src['verse_key'] : '',
					'ayah_id'              		=> isset($src['ayah_id']) ? $src['ayah_id'] : '',
					'ayah_text'            		=> isset($src['ayah_text']) ? $src['ayah_text'] : '',
					'ayah_plain'            	=> isset($src['ayah_plain']) ? $src['ayah_plain'] : '',
					'ayah_transliteration_en'  	=> isset($src['ayah_transliteration_en']) ? $src['ayah_transliteration_en'] : '',
					'ayah_translation_id'  		=> isset($src['ayah_translation_id']) ? $src['ayah_translation_id'] : '',
					'ayah_translation_en'  		=> isset($src['ayah_translation_en']) ? $src['ayah_translation_en'] : '',
					'ayah_tafsir_short_id' 		=> isset($src['ayah_tafsir_short_id']) ? $src['ayah_tafsir_short_id'] : '',
					'ayah_tafsir_long_id'  		=> isset($src['ayah_tafsir_long_id']) ? $src['ayah_tafsir_long_id'] : '',
					'ayah_audio_primary'   		=> isset($src['ayah_audio_primary']) ? $src['ayah_audio_primary'] : '',
					'juz'                  		=> isset($src['juz']) ? $src['juz'] : '',
					'ruku'                  	=> isset($src['ruku']) ? $src['ruku'] : '',
					'manzil'                  	=> isset($src['manzil']) ? $src['manzil'] : ''
				);

				$noAyat++;
			}
		} else {
			$errorMessage = isset($response['error_reason']) ? $response['error_reason'] : 'Data surah tidak ditemukan';
		}
		
		unset($opensearchDev);
		unset($opensearchTBO);
	}	
?>

<?php if(count($ayahList) > 0){ ?>
	<!DOCTYPE html>
	<html lang="id">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title><?php echo !empty($surahInfo) ? htmlspecialchars($surahInfo['chapter_name_latin_id']) : 'Detail Surah'; echo " - Surah - Al-Qur'an Digital"; ?></title>
		<style>
			* {
				box-sizing: border-box;
			}

			body {
				margin: 0;
				padding: 0;
				background: #f8f9fb;
				color: #222;
				font-family: Arial, sans-serif;
			}

			.container {
				max-width: 900px;
				margin: 0 auto;
				padding: 16px;
			}

			.title {
				font-size: 28px;
				font-weight: bold;
				margin-bottom: 20px;
				text-align: center;
			}

			.back-link {
				display: inline-block;
				margin-bottom: 14px;
				text-decoration: none;
				color: #2563eb;
				font-size: 14px;
			}

			.back-link:hover {
				text-decoration: underline;
			}

			.surah-header,
			.player-box {
				background: #fff;
				border: 1px solid #e5e7eb;
				border-radius: 8px;
				padding: 16px;
				margin-bottom: 16px;
			}

			.surah-title {
				margin: 0 0 4px;
				font-size: 24px;
				font-weight: bold;
			}

			.surah-subtitle {
				margin: 0 0 10px;
				font-size: 14px;
				color: #666;
				line-height: 1.6;
			}

			.surah-arabic {
				font-size: 28px;
				text-align: right;
				direction: rtl;
				margin-bottom: 10px;
			}

			.player-label {
				font-size: 14px;
				font-weight: bold;
				margin-bottom: 10px;
			}

			.ayah-item {
				background: #fff;
				border: 1px solid #e5e7eb;
				border-radius: 8px;
				padding: 14px;
				margin-bottom: 12px;
				transition: all 0.25s ease;
			}

			.ayah-item.active-playing {
				border-color: #2563eb;
				box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12);
				background: #f8fbff;
			}

			.ayah-item.active-playing .ayah-no-badge {
				background: #1d4ed8;
				transform: scale(1.05);
			}

			.ayah-top {
				display: flex;
				align-items: center;
				justify-content: space-between;
				margin-bottom: 12px;
			}

			.ayah-no-badge {
				width: 34px;
				height: 34px;
				border-radius: 50%;
				background: #2563eb;
				color: #fff;
				font-size: 14px;
				font-weight: bold;
				display: flex;
				align-items: center;
				justify-content: center;
				line-height: 1;
				box-shadow: 0 2px 6px rgba(37, 99, 235, 0.25);
				transition: all 0.25s ease;
			}

			.ayah-top-right {
				display: flex;
				align-items: center;
			}

			.juz-badge {
				display: inline-block;
				padding: 5px 10px;
				font-size: 12px;
				color: #374151;
				background: #f3f4f6;
				border: 1px solid #e5e7eb;
				border-radius: 999px;
				line-height: 1;
			}

			.ayah-text {
				font-size: 28px;
				line-height: 1.8;
				text-align: right;
				direction: rtl;
				margin-bottom: 12px;
				color: #111827;
			}

			.ayah-translation {
				font-size: 15px;
				line-height: 1.7;
				margin-bottom: 10px;
				color: #333;
			}

			.tafsir-wrapper {
				margin-top: 10px;
				margin-bottom: 10px;
			}

			.tafsir-toggle {
				background: #f3f4f6;
				border: 1px solid #e5e7eb;
				border-radius: 6px;
				padding: 6px 10px;
				font-size: 13px;
				cursor: pointer;
			}

			.tafsir-toggle:hover {
				background: #e5e7eb;
			}

			.ayah-tafsir {
				margin-top: 8px;
				padding: 10px;
				background: #f9fafb;
				border-left: 3px solid #2563eb;
				font-size: 14px;
				line-height: 1.6;
			}

			.tafsir-hidden {
				display: none;
			}

			.audio-player,
			.chapter-player {
				width: 100%;
			}

			.error-box {
				background: #fff;
				border: 1px solid #f5c2c7;
				color: #b42318;
				border-radius: 8px;
				padding: 14px;
			}

			@media (max-width: 768px) {
				.container {
					padding: 12px;
				}

				.surah-title {
					font-size: 20px;
				}

				.surah-arabic {
					font-size: 24px;
				}

				.ayah-text {
					font-size: 22px;
				}

				.ayah-translation,
				.ayah-tafsir {
					font-size: 14px;
				}
			}
		</style>
	</head>
	<body>
		<div class="container">
			<a href="quran.php" class="back-link">&larr; Kembali</a>
			
			<div class="title">Al-Qur'an Digital</div>
			
			<?php if (!empty($errorMessage)): ?>
				<div class="error-box">
					<?php echo htmlspecialchars($errorMessage); ?>
				</div>
			<?php else: ?>
				<div class="surah-header">
					<h1 class="surah-title">
						<?php echo htmlspecialchars($surahInfo['chapter_id']); ?>. 
						<?php echo htmlspecialchars($surahInfo['chapter_name_latin_id']); ?>
					</h1>

					<div class="surah-subtitle">
						<?php echo htmlspecialchars($surahInfo['chapter_translation_id']); ?> | <?php echo htmlspecialchars($surahInfo['chapter_total_verses']); ?> Ayat<br>
						<?php echo htmlspecialchars($surahInfo['chapter_type_id']); ?><br>
					</div>

					<div class="surah-arabic">
						<?php echo htmlspecialchars($surahInfo['surah_name']); ?>
					</div>
				</div>
				
				<?php
				$chapterHlsUrl = "https://asset-2.tribunnews.com/tribunnews/alquran/hls/" . $surahInfo['chapter_id'] . "/chapter.m3u8";
				?>
				<div class="player-box">
					<div class="player-label">Surat <?php echo htmlspecialchars($surahInfo['chapter_name_latin_id']); ?></div>
					<audio id="chapter-player"
						   class="chapter-player"
						   data-hls="<?php echo htmlspecialchars($chapterHlsUrl); ?>"
						   controls
						   preload="none"></audio>
				</div>

				<?php foreach ($ayahList as $index => $ayah): ?>
					<div class="ayah-item" id="ayah-<?php echo $ayah['no_ayat']; ?>" data-ayah-index="<?php echo $index; ?>">
						<div class="ayah-top">
							<div class="ayah-no-badge">
								<?php echo htmlspecialchars($ayah['no_ayat']); ?>
							</div>

							<div class="ayah-top-right">
								<a href="quran_juz_detail.php?juz=<?php echo urlencode($ayah['juz']); ?>"><span class="juz-badge">Juz <?php echo htmlspecialchars($ayah['juz']); ?></span></a>
							</div>
						</div>

						<div class="ayah-text">
							<?php echo nl2br(htmlspecialchars($ayah['ayah_text'])); ?>
						</div>

						<div class="ayah-translation">
							<strong><?php echo nl2br(htmlspecialchars($ayah['ayah_transliteration_en'])); ?></strong><br>
							<?php echo nl2br(htmlspecialchars($ayah['ayah_translation_id'])); ?>
						</div>

						<?php if (!empty($ayah['ayah_tafsir_short_id']) || !empty($ayah['ayah_tafsir_long_id'])): ?>
							<div class="tafsir-wrapper">

								<button class="tafsir-toggle" data-index="<?php echo $index; ?>">
									Lihat Tafsir
								</button>

								<div class="ayah-tafsir tafsir-hidden" id="tafsir-<?php echo $index; ?>">
									<?php echo nl2br(htmlspecialchars($ayah['ayah_tafsir_short_id'])); ?>
									
									<br><br><hr><br>
									
									<?php echo nl2br(htmlspecialchars($ayah['ayah_tafsir_long_id'])); ?>
									
									<p>Sumber: kemenag.go.id</p>
								</div>

							</div>
						<?php endif; ?>
						
						
						<?php if (!empty($ayah['verse_key'])): ?>
							<?php
							$verse_key = str_replace(":", "_", $ayah['verse_key']);
							$url_mp3 = "https://asset-2.tribunnews.com/tribunnews/alquran/mp3/".$surahInfo['chapter_id']."/".$verse_key.".mp3";
							$url_hls = "https://asset-2.tribunnews.com/tribunnews/alquran/hls/".$surahInfo['chapter_id']."/".$verse_key."/index.m3u8";
							?>
							<audio class="audio-player"
								   data-index="<?php echo $index; ?>"
								   data-hls="<?php echo htmlspecialchars($url_hls); ?>"
								   data-fallback="<?php echo htmlspecialchars($url_mp3); ?>"
								   controls
								   preload="none">
							</audio>
						<?php endif; ?>
					</div>
				<?php endforeach; ?>
			<?php endif; ?>
		</div>
		
		<script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
		<script>
		document.addEventListener('DOMContentLoaded', function () {
			document.querySelectorAll('.tafsir-toggle').forEach(function (btn) {
				btn.addEventListener('click', function () {
					const index = this.dataset.index;
					const tafsir = document.getElementById('tafsir-' + index);

					if (!tafsir) return;

					if (tafsir.classList.contains('tafsir-hidden')) {
						tafsir.classList.remove('tafsir-hidden');
						this.textContent = 'Sembunyikan Tafsir';
					} else {
						tafsir.classList.add('tafsir-hidden');
						this.textContent = 'Lihat Tafsir';
					}
				});
			});

			const ayahPlayers = Array.from(document.querySelectorAll('.audio-player'));
			const chapterPlayer = document.getElementById('chapter-player');
			const ayahItems = Array.from(document.querySelectorAll('.ayah-item'));
			const FALLBACK_TIMEOUT = 3000;

			function clearActiveAyah() {
				ayahItems.forEach(function (item) {
					item.classList.remove('active-playing');
				});
			}

			function setActiveAyah(index) {
				clearActiveAyah();

				const currentAyah = document.querySelector('.ayah-item[data-ayah-index="' + index + '"]');
				if (currentAyah) {
					currentAyah.classList.add('active-playing');
					currentAyah.scrollIntoView({
						behavior: 'smooth',
						block: 'center'
					});
				}
			}

			function destroyHls(player) {
				if (player && player._hls) {
					player._hls.destroy();
					player._hls = null;
				}
			}

			function clearTimer(player) {
				if (player && player._fallbackTimer) {
					clearTimeout(player._fallbackTimer);
					player._fallbackTimer = null;
				}
			}

			function stopChapterPlayer() {
				if (!chapterPlayer) return;
				clearTimer(chapterPlayer);
				chapterPlayer.pause();
				chapterPlayer.currentTime = 0;
				chapterPlayer.dataset.shouldPlay = 'false';
			}

			function stopOtherAyahPlayers(activeIndex) {
				ayahPlayers.forEach(function (player, idx) {
					if (idx !== activeIndex) {
						clearTimer(player);
						player.pause();
						player.currentTime = 0;
						player.dataset.shouldPlay = 'false';
					}
				});
			}

			function loadHls(player, url) {
				destroyHls(player);

				if (!url) return false;

				if (player.canPlayType('application/vnd.apple.mpegurl')) {
					player.src = url;
					return true;
				}

				if (window.Hls && Hls.isSupported()) {
					const hls = new Hls();
					hls.loadSource(url);
					hls.attachMedia(player);
					player._hls = hls;
					return true;
				}

				return false;
			}

			function loadMp3(player, url) {
				destroyHls(player);

				if (!url) return false;

				player.src = url;
				return true;
			}

			function tryPlay(player) {
				if (!player) return;

				player.dataset.shouldPlay = 'true';

				const promise = player.play();
				if (promise && typeof promise.catch === 'function') {
					promise.catch(function (err) {
						console.log('Play gagal:', err);
					});
				}
			}

			function switchAyahToFallback(player) {
				if (!player) return;
				if (player.dataset.fallbackUsed === 'true') return;

				const fallback = player.dataset.fallback || '';
				if (!fallback) return;

				player.dataset.fallbackUsed = 'true';
				clearTimer(player);

				loadMp3(player, fallback);
				player.load();

				if (player.dataset.shouldPlay === 'true') {
					player.addEventListener('canplay', function onCanPlay() {
						player.removeEventListener('canplay', onCanPlay);
						tryPlay(player);
					});
				}
			}

			function startAyahFallbackTimeout(player) {
				clearTimer(player);

				if (!player) return;
				if (player.dataset.fallbackUsed === 'true') return;

				player._fallbackTimer = setTimeout(function () {
					const shouldPlay = player.dataset.shouldPlay === 'true';
					const ready = player.readyState >= 3;

					if (shouldPlay && !ready) {
						switchAyahToFallback(player);
					}
				}, FALLBACK_TIMEOUT);
			}

			function initAyahPlayer(player, index) {
				player.dataset.index = index;
				player.dataset.shouldPlay = 'false';
				player.dataset.fallbackUsed = 'false';

				const hlsUrl = player.dataset.hls || '';
				loadHls(player, hlsUrl);

				player.addEventListener('play', function () {
					player.dataset.shouldPlay = 'true';
					stopOtherAyahPlayers(index);
					stopChapterPlayer();
					setActiveAyah(index);
					startAyahFallbackTimeout(player);
				});

				player.addEventListener('pause', function () {
					if (!player.ended) {
						player.dataset.shouldPlay = 'false';
						clearTimer(player);

						const currentAyah = document.querySelector('.ayah-item[data-ayah-index="' + index + '"]');
						if (currentAyah) {
							currentAyah.classList.remove('active-playing');
						}
					}
				});

				player.addEventListener('ended', function () {
					player.dataset.shouldPlay = 'false';
					clearTimer(player);

					const nextIndex = index + 1;

					if (ayahPlayers[nextIndex]) {
						setActiveAyah(nextIndex);
						tryPlay(ayahPlayers[nextIndex]);
					} else {
						clearActiveAyah();
					}
				});

				player.addEventListener('canplay', function () {
					clearTimer(player);
				});

				player.addEventListener('playing', function () {
					clearTimer(player);
				});

				player.addEventListener('loadeddata', function () {
					clearTimer(player);
				});

				player.addEventListener('waiting', function () {
					if (player.dataset.shouldPlay === 'true' && player.dataset.fallbackUsed !== 'true') {
						startAyahFallbackTimeout(player);
					}
				});

				player.addEventListener('stalled', function () {
					if (player.dataset.shouldPlay === 'true' && player.dataset.fallbackUsed !== 'true') {
						startAyahFallbackTimeout(player);
					}
				});

				player.addEventListener('error', function () {
					switchAyahToFallback(player);
				});

				if (player._hls) {
					player._hls.on(Hls.Events.ERROR, function (event, data) {
						if (data && data.fatal) {
							switchAyahToFallback(player);
						}
					});
				}
			}

			function initChapterPlayer(player) {
				if (!player) return;

				player.dataset.shouldPlay = 'false';

				const hlsUrl = player.dataset.hls || '';
				loadHls(player, hlsUrl);

				player.addEventListener('play', function () {
					player.dataset.shouldPlay = 'true';

					ayahPlayers.forEach(function (ayahPlayer) {
						clearTimer(ayahPlayer);
						ayahPlayer.pause();
						ayahPlayer.currentTime = 0;
						ayahPlayer.dataset.shouldPlay = 'false';
					});

					clearActiveAyah();
				});

				player.addEventListener('pause', function () {
					if (!player.ended) {
						player.dataset.shouldPlay = 'false';
					}
				});

				player.addEventListener('error', function () {
					console.log('Chapter HLS gagal diputar');
				});

				if (player._hls) {
					player._hls.on(Hls.Events.ERROR, function (event, data) {
						if (data && data.fatal) {
							console.log('Chapter HLS fatal error', data);
						}
					});
				}
			}
			
			function scrollToAyahFromHash() {
				const hash = window.location.hash;

				if (!hash) return;

				const ayahNumber = hash.replace('#', '');

				if (!ayahNumber || isNaN(ayahNumber)) return;

				const target = document.getElementById('ayah-' + ayahNumber);

				if (target) {
					setTimeout(() => {
						target.scrollIntoView({
							behavior: 'smooth',
							block: 'center'
						});

						target.classList.add('active-playing');

						setTimeout(() => {
							target.classList.remove('active-playing');
						}, 3000);
					}, 300); 
					
					const index = parseInt(target.dataset.ayahIndex);

					if (!isNaN(index) && ayahPlayers[index]) {
						tryPlay(ayahPlayers[index]);
					}
				}
			}

			initChapterPlayer(chapterPlayer);

			ayahPlayers.forEach(function (player, index) {
				initAyahPlayer(player, index);
			});
			
			scrollToAyahFromHash();
			
			window.addEventListener('hashchange', scrollToAyahFromHash);
		});
		</script>
	</body>
	</html>
<?php } ?>

<?php } ?>