"use strict";

(function threatGlobe() {
    const canvas = document.getElementById("network-globe");
    if (!canvas) {
        return;
    }
    const context = canvas.getContext("2d");
    const dots = [];
    const threats = [
        {lat: 31.2, lon: 121.5},
        {lat: 1.35, lon: 103.8},
        {lat: 37.8, lon: -122.4},
        {lat: 51.5, lon: -0.1},
    ];
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let rotation = 0;

    for (let lat = -80; lat <= 80; lat += 10) {
        for (let lon = -180; lon < 180; lon += 10) {
            dots.push({lat: lat * Math.PI / 180, lon: lon * Math.PI / 180});
        }
    }

    /** 将球面坐标投影到二维画布。 */
    function project(point, centerX, centerY, radius, angle) {
        const longitude = point.lon + angle;
        const cosLatitude = Math.cos(point.lat);
        let x = cosLatitude * Math.sin(longitude);
        let y = Math.sin(point.lat);
        let z = cosLatitude * Math.cos(longitude);
        const tilt = -0.24;
        const tiltedY = y * Math.cos(tilt) - z * Math.sin(tilt);
        z = y * Math.sin(tilt) + z * Math.cos(tilt);
        y = tiltedY;
        return {
            x: centerX + x * radius,
            y: centerY - y * radius,
            z,
            visible: z > -0.02,
        };
    }

    /** 将经纬度转换为画布球面坐标。 */
    function locationPoint(location) {
        return {
            lat: location.lat * Math.PI / 180,
            lon: location.lon * Math.PI / 180,
        };
    }

    /** 绘制点阵地球和少量威胁节点连线。 */
    function draw(timestamp = 0) {
        const width = canvas.clientWidth || 360;
        const height = canvas.clientHeight || 220;
        const dpr = window.devicePixelRatio || 1;
        if (canvas.width !== Math.round(width * dpr) || canvas.height !== Math.round(height * dpr)) {
            canvas.width = Math.round(width * dpr);
            canvas.height = Math.round(height * dpr);
        }
        context.setTransform(dpr, 0, 0, dpr, 0, 0);
        context.clearRect(0, 0, width, height);
        const centerX = width / 2;
        const centerY = height / 2 + 4;
        const radius = Math.min(width, height) * 0.38;
        const visibleThreats = [];

        dots.forEach((dot) => {
            const point = project(dot, centerX, centerY, radius, rotation);
            if (!point.visible) {
                return;
            }
            const alpha = 0.12 + (point.z + 1) * 0.24;
            context.beginPath();
            context.fillStyle = `rgba(138, 150, 164, ${alpha})`;
            context.arc(point.x, point.y, point.z > 0.65 ? 1.25 : 0.9, 0, Math.PI * 2);
            context.fill();
        });

        threats.forEach((location) => {
            const point = project(locationPoint(location), centerX, centerY, radius, rotation);
            if (point.visible) {
                visibleThreats.push(point);
                const pulse = 2.3 + Math.sin(timestamp / 360 + point.x) * 0.8;
                context.beginPath();
                context.fillStyle = "rgba(244, 165, 140, 0.95)";
                context.arc(point.x, point.y, pulse, 0, Math.PI * 2);
                context.fill();
                context.beginPath();
                context.strokeStyle = "rgba(244, 165, 140, 0.2)";
                context.lineWidth = 1;
                context.arc(point.x, point.y, 7 + pulse, 0, Math.PI * 2);
                context.stroke();
            }
        });

        for (let index = 0; index < visibleThreats.length - 1; index += 1) {
            const start = visibleThreats[index];
            const end = visibleThreats[index + 1];
            context.beginPath();
            context.strokeStyle = "rgba(244, 165, 140, 0.12)";
            context.lineWidth = 0.8;
            context.moveTo(start.x, start.y);
            context.quadraticCurveTo(centerX, centerY - radius * 0.7, end.x, end.y);
            context.stroke();
        }

        if (!prefersReducedMotion) {
            rotation += 0.0028;
            window.requestAnimationFrame(draw);
        }
    }

    draw(0);
}());
