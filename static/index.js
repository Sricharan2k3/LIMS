function expand() {
  var details = document.getElementById("details");

  if (details.style.display === "block") {
    details.style.display = "none";
  } else {
    details.style.display = "block";
  }
}
// function expand() {
//   var down = document.getElementById("down");
//   down.addEventListener("click", function () {
//     var details = document.getElementById("details");
//     if (details.style.display === "block") {
//       content.style.display = "none";
//     } else {
//       details.style.display = "block";
//     }
//   });
// }
