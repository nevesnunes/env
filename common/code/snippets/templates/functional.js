const grouped = penguins
	.filter((penguin) => penguin.male)
	.reduce((memo, penguin) => {
		const current = memo[penguin.age] || [];
		const group = {[penguin.age]: [...current, penguin.name]};

		return Object.assign({}, memo, group);
	},{});

const aggregated = cars.reduce((memo, car) => {
	const {wheels, transmissions} = memo;

	return {
		wheels: wheels + (car.wheels || 0),
		transmissions: transmissions + (car.transmission || 0)
	};
},{wheels: 0, transmissions: 0});

const wheels = (() => {
	if (needsWheels()) {
		return {wheels: howManyWheels()};
	}
})();

const transmission = (() => {
	if (needsTransmission()) {
		return {transmission: 1};
	}
})();

const shoppingList = Object.assign({}, wheels, transmission);
