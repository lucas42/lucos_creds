import 'lucos_navbar';

document.querySelectorAll(".view-credential .value").forEach(valueNode => {
	const text = valueNode.textContent;
	const copyButton = document.createElement("button");
	copyButton.textContent = "📋";
	copyButton.classList.add("copy-button");
	copyButton.title = "Copy this value to clipboard";
	copyButton.addEventListener("click", async event => {
		await navigator.clipboard.writeText(valueNode.textContent);
		copyButton.dataset.copied = true;
		copyButton.offsetHeight; // Force a repaint for the transition effect to take place
		delete copyButton.dataset.copied;
	});
	valueNode.parentNode.appendChild(copyButton);
});