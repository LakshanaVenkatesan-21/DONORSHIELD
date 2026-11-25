document.addEventListener("DOMContentLoaded", () => {
  const typeSelect = document.getElementById("donationType");
  const organRow   = document.getElementById("organRow");
  if (typeSelect && organRow) {
    typeSelect.addEventListener("change", () => {
      organRow.style.display = typeSelect.value === "organ" ? "block" : "none";
    });
  }
});
